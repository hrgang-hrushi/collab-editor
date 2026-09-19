use crate::shaders::TEXT_WGSL_SHADER;
use bytemuck::{Pod, Zeroable};
use std::sync::Arc;
use wgpu::util::DeviceExt;

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct Uniforms {
    pub viewport_size: [f32; 2],
    pub scroll_offset: [f32; 2],
    pub char_size: [f32; 2],
    pub cursor_pos: [f32; 2],
    pub cursor_visible: f32,
    pub time: f32,
    pub _padding: [f32; 2],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct Vertex {
    pub position: [f32; 2],
    pub uv: [f32; 2],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct GlyphInstance {
    pub char_pos: [f32; 2],
    pub atlas_coords: [f32; 4],
    pub color: [f32; 4],
    pub is_cursor: f32,
}

pub struct WgpuRenderer {
    pub surface: Option<wgpu::Surface<'static>>,
    pub device: Arc<wgpu::Device>,
    pub queue: Arc<wgpu::Queue>,
    pub config: wgpu::SurfaceConfiguration,
    pub render_pipeline: wgpu::RenderPipeline,
    pub uniform_buffer: wgpu::Buffer,
    pub uniform_bind_group: wgpu::BindGroup,
    pub vertex_buffer: wgpu::Buffer,
    pub instance_buffer: Option<wgpu::Buffer>,
    pub num_instances: u32,
    pub font_texture: wgpu::Texture,
    pub font_sampler: wgpu::Sampler,
    pub width: u32,
    pub height: u32,
    pub cursor_line: usize,
    pub cursor_col: usize,
    pub scroll_y: f32,
    pub start_time: f64,
}

const QUAD_VERTICES: &[Vertex] = &[
    Vertex { position: [0.0, 0.0], uv: [0.0, 0.0] },
    Vertex { position: [1.0, 0.0], uv: [1.0, 0.0] },
    Vertex { position: [0.0, 1.0], uv: [0.0, 1.0] },
    Vertex { position: [1.0, 0.0], uv: [1.0, 0.0] },
    Vertex { position: [1.0, 1.0], uv: [1.0, 1.0] },
    Vertex { position: [0.0, 1.0], uv: [0.0, 1.0] },
];

impl WgpuRenderer {
    pub async fn new_headless(width: u32, height: u32) -> Result<Self, String> {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::Backends::all(),
            ..Default::default()
        });

        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface: None,
                force_fallback_adapter: false,
            })
            .await
            .ok_or_else(|| "Failed to find suitable WebGPU adapter".to_string())?;

        let (device, queue) = adapter
            .request_device(
                &wgpu::DeviceDescriptor {
                    required_features: wgpu::Features::empty(),
                    required_limits: wgpu::Limits::downlevel_webgl2_defaults(),
                    label: Some("Crex WebGPU Device"),
                },
                None,
            )
            .await
            .map_err(|e| e.to_string())?;

        let device = Arc::new(device);
        let queue = Arc::new(queue);

        let format = wgpu::TextureFormat::Bgra8Unorm;
        let config = wgpu::SurfaceConfiguration {
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            format,
            width,
            height,
            present_mode: wgpu::PresentMode::AutoVsync,
            alpha_mode: wgpu::CompositeAlphaMode::Opaque,
            view_formats: vec![],
            desired_maximum_frame_latency: 2,
        };

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("Text Shader"),
            source: wgpu::ShaderSource::Wgsl(TEXT_WGSL_SHADER.into()),
        });

        // 256x256 monochrome font atlas texture
        let font_texture = device.create_texture(&wgpu::TextureDescriptor {
            label: Some("Font Atlas Texture"),
            size: wgpu::Extent3d {
                width: 256,
                height: 256,
                depth_or_array_layers: 1,
            },
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: wgpu::TextureFormat::R8Unorm,
            usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
            view_formats: &[],
        });

        let font_view = font_texture.create_view(&wgpu::TextureViewDescriptor::default());
        let font_sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            address_mode_u: wgpu::AddressMode::ClampToEdge,
            address_mode_v: wgpu::AddressMode::ClampToEdge,
            mag_filter: wgpu::FilterMode::Nearest,
            min_filter: wgpu::FilterMode::Nearest,
            ..Default::default()
        });

        let uniforms = Uniforms {
            viewport_size: [width as f32, height as f32],
            scroll_offset: [0.0, 0.0],
            char_size: [9.6, 20.0],
            cursor_pos: [56.0, 0.0],
            cursor_visible: 1.0,
            time: 0.0,
            _padding: [0.0, 0.0],
        };

        let uniform_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Uniform Buffer"),
            contents: bytemuck::cast_slice(&[uniforms]),
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
        });

        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("Bind Group Layout"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::VERTEX_FRAGMENT,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Texture {
                        sample_type: wgpu::TextureSampleType::Float { filterable: true },
                        view_dimension: wgpu::TextureViewDimension::D2,
                        multisampled: false,
                    },
                    count: None,
                },
            ],
        });

        let uniform_bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("Uniform Bind Group"),
            layout: &bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: uniform_buffer.as_overall_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: wgpu::BindingResource::Sampler(&font_sampler),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: wgpu::BindingResource::TextureView(&font_view),
                },
            ],
        });

        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("Render Pipeline Layout"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });

        let render_pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("Render Pipeline"),
            layout: Some(&pipeline_layout),
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: "vs_main",
                buffers: &[
                    // Vertex buffer layout
                    wgpu::VertexBufferLayout {
                        array_stride: std::mem::size_of::<Vertex>() as wgpu::BufferAddress,
                        step_mode: wgpu::VertexStepMode::Vertex,
                        attributes: &[
                            wgpu::VertexAttribute {
                                offset: 0,
                                shader_location: 0,
                                format: wgpu::VertexFormat::Float32x2,
                            },
                            wgpu::VertexAttribute {
                                offset: 8,
                                shader_location: 1,
                                format: wgpu::VertexFormat::Float32x2,
                            },
                        ],
                    },
                    // Instance buffer layout
                    wgpu::VertexBufferLayout {
                        array_stride: std::mem::size_of::<GlyphInstance>() as wgpu::BufferAddress,
                        step_mode: wgpu::VertexStepMode::Instance,
                        attributes: &[
                            wgpu::VertexAttribute {
                                offset: 0,
                                shader_location: 2,
                                format: wgpu::VertexFormat::Float32x2,
                            },
                            wgpu::VertexAttribute {
                                offset: 8,
                                shader_location: 3,
                                format: wgpu::VertexFormat::Float32x4,
                            },
                            wgpu::VertexAttribute {
                                offset: 24,
                                shader_location: 4,
                                format: wgpu::VertexFormat::Float32x4,
                            },
                            wgpu::VertexAttribute {
                                offset: 40,
                                shader_location: 5,
                                format: wgpu::VertexFormat::Float32,
                            },
                        ],
                    },
                ],
            },
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: "fs_main",
                targets: &[Some(wgpu::ColorTargetState {
                    format,
                    blend: Some(wgpu::BlendState::ALPHA_BLENDING),
                    write_mask: wgpu::ColorWrites::ALL,
                })],
            }),
            primitive: wgpu::PrimitiveState {
                topology: wgpu::PrimitiveTopology::TriangleList,
                strip_index_format: None,
                front_face: wgpu::FrontFace::Ccw,
                cull_mode: None,
                polygon_mode: wgpu::PolygonMode::Fill,
                unclipped_depth: false,
                conservative: false,
            },
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            multiview: None,
        });

        let vertex_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Quad Vertex Buffer"),
            contents: bytemuck::cast_slice(QUAD_VERTICES),
            usage: wgpu::BufferUsages::VERTEX,
        });

        Ok(Self {
            surface: None,
            device,
            queue,
            config,
            render_pipeline,
            uniform_buffer,
            uniform_bind_group,
            vertex_buffer,
            instance_buffer: None,
            num_instances: 0,
            font_texture,
            font_sampler,
            width,
            height,
            cursor_line: 0,
            cursor_col: 0,
            scroll_y: 0.0,
            start_time: 0.0,
        })
    }

    /// Builds instances for gutter numbers, code glyphs, and the 500ms blinking cursor
    pub fn update_buffer_layout(&mut self, text: &str, current_time_ms: f64) {
        let lines: Vec<&str> = text.lines().collect();
        let mut instances: Vec<GlyphInstance> = Vec::new();

        let char_w = 9.6f32;
        let line_h = 20.0f32;
        let gutter_w = 48.0f32;
        let padding_x = 8.0f32;

        let white_color = [1.0, 1.0, 1.0, 1.0];
        let gutter_color = [0.266, 0.266, 0.266, 1.0]; // #444444

        for (line_idx, line) in lines.iter().enumerate() {
            let y = line_idx as f32 * line_h;

            // Render line number in gutter
            let line_no_str = format!("{:>3}", line_idx + 1);
            for (col_idx, c) in line_no_str.chars().enumerate() {
                let x = col_idx as f32 * char_w + padding_x;
                let ascii = c as u32;
                let u = (ascii % 16) as f32 / 16.0;
                let v = (ascii / 16) as f32 / 16.0;
                instances.push(GlyphInstance {
                    char_pos: [x, y],
                    atlas_coords: [u, v, u + 1.0 / 16.0, v + 1.0 / 16.0],
                    color: gutter_color,
                    is_cursor: 0.0,
                });
            }

            // Render code text
            for (col_idx, c) in line.chars().enumerate() {
                let x = gutter_w + padding_x + col_idx as f32 * char_w;
                let ascii = c as u32;
                let u = (ascii % 16) as f32 / 16.0;
                let v = (ascii / 16) as f32 / 16.0;
                instances.push(GlyphInstance {
                    char_pos: [x, y],
                    atlas_coords: [u, v, u + 1.0 / 16.0, v + 1.0 / 16.0],
                    color: white_color,
                    is_cursor: 0.0,
                });
            }
        }

        // Active 1px solid white cursor with hard 500ms toggle
        let cursor_x = gutter_w + padding_x + self.cursor_col as f32 * char_w;
        let cursor_y = self.cursor_line as f32 * line_h;
        let cursor_visible = if ((current_time_ms / 500.0) as u64) % 2 == 0 { 1.0 } else { 0.0 };

        instances.push(GlyphInstance {
            char_pos: [cursor_x, cursor_y],
            atlas_coords: [0.0, 0.0, 1.0, 1.0],
            color: white_color,
            is_cursor: 1.0,
        });

        self.num_instances = instances.len() as u32;

        self.instance_buffer = Some(self.device.create_buffer_init(
            &wgpu::util::BufferInitDescriptor {
                label: Some("Glyph Instance Buffer"),
                contents: bytemuck::cast_slice(&instances),
                usage: wgpu::BufferUsages::VERTEX,
            },
        ));

        // Update uniforms
        let uniforms = Uniforms {
            viewport_size: [self.width as f32, self.height as f32],
            scroll_offset: [0.0, self.scroll_y],
            char_size: [char_w, line_h],
            cursor_pos: [cursor_x, cursor_y],
            cursor_visible,
            time: (current_time_ms / 1000.0) as f32,
            _padding: [0.0, 0.0],
        };

        self.queue.write_buffer(
            &self.uniform_buffer,
            0,
            bytemuck::cast_slice(&[uniforms]),
        );
    }
}
