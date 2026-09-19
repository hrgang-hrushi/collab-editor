pub const TEXT_WGSL_SHADER: &str = r#"
struct Uniforms {
    viewport_size: vec2<f32>,
    scroll_offset: vec2<f32>,
    char_size: vec2<f32>,
    cursor_pos: vec2<f32>,
    cursor_visible: f32,
    time: f32,
};

@group(0) @binding(0)
var<uniform> uniforms: Uniforms;

@group(0) @binding(1)
var font_sampler: sampler;

@group(0) @binding(2)
var font_texture: texture_2d<f32>;

struct VertexInput {
    @location(0) position: vec2<f32>,
    @location(1) uv: vec2<f32>,
};

struct InstanceInput {
    @location(2) char_pos: vec2<f32>,
    @location(3) atlas_coords: vec4<f32>, // u_min, v_min, u_max, v_max
    @location(4) color: vec4<f32>,
    @location(5) is_cursor: f32,
};

struct VertexOutput {
    @builtin(position) clip_position: vec4<f32>,
    @location(0) uv: vec2<f32>,
    @location(1) color: vec4<f32>,
    @location(2) is_cursor: f32,
};

@vertex
fn vs_main(model: VertexInput, instance: InstanceInput) -> VertexOutput {
    var out: VertexOutput;
    
    var world_pos = instance.char_pos + model.position * uniforms.char_size - uniforms.scroll_offset;
    
    // Normalize coordinates to WebGPU clip space [-1, 1]
    var ndc_x = (world_pos.x / uniforms.viewport_size.x) * 2.0 - 1.0;
    var ndc_y = 1.0 - (world_pos.y / uniforms.viewport_size.y) * 2.0;
    
    out.clip_position = vec4<f32>(ndc_x, ndc_y, 0.0, 1.0);
    
    // Map quad UV to glyph atlas UV
    out.uv = mix(instance.atlas_coords.xy, instance.atlas_coords.zw, model.uv);
    out.color = instance.color;
    out.is_cursor = instance.is_cursor;
    
    return out;
}

@fragment
fn fs_main(in: VertexOutput) -> @location(0) vec4<f32> {
    if (in.is_cursor > 0.5) {
        if (uniforms.cursor_visible > 0.5) {
            return vec4<f32>(1.0, 1.0, 1.0, 1.0); // Solid #FFFFFF cursor
        } else {
            discard;
        }
    }
    
    let alpha = textureSample(font_texture, font_sampler, in.uv).r;
    if (alpha < 0.05) {
        discard;
    }
    
    return vec4<f32>(in.color.rgb, in.color.a * alpha);
}
"#;
