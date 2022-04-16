use sdl2::event::Event;
use sdl2::keyboard::Keycode;
use sdl2::pixels::Color;
use sdl2::rect::Rect;
use sdl2::render::TextureQuery;

const SCREEN_WIDTH: u32 = 600;
const SCREEN_HEIGHT: u32 = 400;

pub(crate) fn render(data: &Vec<(String, crate::Color)>) -> Result<(), String> {
    let sdl_context = sdl2::init()?;
    let video_subsys = sdl_context.video()?;
    let ttf_context = sdl2::ttf::init().map_err(|e| e.to_string())?;

    let window = video_subsys
        .window("CCF checker", SCREEN_WIDTH, SCREEN_HEIGHT)
        .position_centered()
        .opengl()
        .build()
        .map_err(|e| e.to_string())?;

    let mut canvas = window.into_canvas().build().map_err(|e| e.to_string())?;
    let texture_creator = canvas.texture_creator();

    const FONT_DATA: &[u8] = include_bytes!("../fusion-pixel.ttf");
    let font =
        ttf_context.load_font_from_rwops(sdl2::rwops::RWops::from_bytes(FONT_DATA).unwrap(), 18)?;

    canvas.set_draw_color(Color::RGBA(0, 0, 0, 255));
    canvas.clear();

    let mut base_x = 0;

    for (t, c) in data.iter() {
        let surface = font
            .render(t)
            .blended_wrapped(
                match c {
                    crate::Color::Red => Color::RGBA(255, 0, 0, 255),
                    crate::Color::Yellow => Color::RGBA(0, 255, 255, 255),
                    crate::Color::Green => Color::RGBA(0, 255, 0, 255),
                    crate::Color::Black => Color::RGBA(0, 0, 0, 255),
                },
                SCREEN_WIDTH,
            )
            .map_err(|e| e.to_string())?;
        let texture = texture_creator
            .create_texture_from_surface(&surface)
            .map_err(|e| e.to_string())?;

        let TextureQuery { width, height, .. } = texture.query();

        let target = Rect::new(base_x, 0, width, height);
        base_x += height as i32;

        canvas.copy(&texture, None, Some(target))?;
    }

    canvas.present();

    'mainloop: loop {
        for event in sdl_context.event_pump()?.poll_iter() {
            match event {
                Event::KeyDown {
                    keycode: Some(Keycode::Escape),
                    ..
                }
                | Event::Quit { .. } => break 'mainloop,
                _ => {}
            }
        }
    }

    Ok(())
}