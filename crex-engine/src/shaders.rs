/// WGSL Shaders for Crex Bare-Metal WebGPU Pipeline

pub const GLYPH_SHADER_WGSL: &str = r#"
struct Uniforms {
    viewport_size: vec2<f32>,
    char_size: vec2<f32>,
    offset: vec2<f32>,
    time: f32,
    _pad: f32,
};

@group(0) @binding(0) var<uniform> uniforms: Uniforms;
@group(0) @binding(1) var atlas_texture: texture_2d<f32>;
@group(0) @binding(2) var atlas_sampler: sampler;

struct VertexInput {
    @builtin(vertex_index) vertex_index: u32,
    @location(0) pos: vec2<f32>,       // grid x, y
    @location(1) uv_offset: vec2<f32>, // atlas UV offset
    @location(2) color: vec4<f32>,     // RGBA
};

struct VertexOutput {
    @builtin(position) clip_position: vec4<f32>,
    @location(0) uv: vec2<f32>,
    @location(1) color: vec4<f32>,
};

@vertex
fn vs_main(in: VertexInput) -> VertexOutput {
    var quad_verts = array<vec2<f32>, 6>(
        vec2<f32>(0.0, 0.0),
        vec2<f32>(1.0, 0.0),
        vec2<f32>(0.0, 1.0),
        vec2<f32>(1.0, 0.0),
        vec2<f32>(1.0, 1.0),
        vec2<f32>(0.0, 1.0)
    );

    let unit = quad_verts[in.vertex_index % 6u];
    let pixel_pos = in.pos * uniforms.char_size - uniforms.offset + unit * uniforms.char_size;

    // Convert pixel coords to NDC (-1 to 1, with Y down)
    let ndc_x = (pixel_pos.x / uniforms.viewport_size.x) * 2.0 - 1.0;
    let ndc_y = 1.0 - (pixel_pos.y / uniforms.viewport_size.y) * 2.0;

    var out: VertexOutput;
    out.clip_position = vec4<f32>(ndc_x, ndc_y, 0.0, 1.0);
    out.uv = in.uv_offset + unit * (uniforms.char_size / 512.0);
    out.color = in.color;
    return out;
}

@fragment
fn fs_main(in: VertexOutput) -> @location(0) vec4<f32> {
    let alpha = textureSample(atlas_texture, atlas_sampler, in.uv).r;
    return vec4<f32>(in.color.rgb, in.color.a * alpha);
}
"#;

pub const RECT_SHADER_WGSL: &str = r#"
struct Uniforms {
    viewport_size: vec2<f32>,
    cursor_blink: f32, // 1.0 = visible, 0.0 = hidden
    _pad: f32,
};

@group(0) @binding(0) var<uniform> uniforms: Uniforms;

struct RectInstance {
    @location(0) rect: vec4<f32>,  // x, y, width, height
    @location(1) color: vec4<f32>, // RGBA
};

struct VertexOutput {
    @builtin(position) clip_position: vec4<f32>,
    @location(0) color: vec4<f32>,
};

@vertex
fn vs_main(
    @builtin(vertex_index) vertex_index: u32,
    instance: RectInstance
) -> VertexOutput {
    var quad = array<vec2<f32>, 6>(
        vec2<f32>(0.0, 0.0),
        vec2<f32>(1.0, 0.0),
        vec2<f32>(0.0, 1.0),
        vec2<f32>(1.0, 0.0),
        vec2<f32>(1.0, 1.0),
        vec2<f32>(0.0, 1.0)
    );

    let unit = quad[vertex_index % 6u];
    let pixel_pos = instance.rect.xy + unit * instance.rect.zw;

    let ndc_x = (pixel_pos.x / uniforms.viewport_size.x) * 2.0 - 1.0;
    let ndc_y = 1.0 - (pixel_pos.y / uniforms.viewport_size.y) * 2.0;

    var out: VertexOutput;
    out.clip_position = vec4<f32>(ndc_x, ndc_y, 0.0, 1.0);
    out.color = instance.color;
    return out;
}

@fragment
fn fs_main(in: VertexOutput) -> @location(0) vec4<f32> {
    return in.color;
}
"#;
