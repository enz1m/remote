use super::*;

pub(crate) fn send(a: &mut App, message: Message) {
    let task = a.update(message);
    send_task(a, task);
}

pub(crate) fn send_task(a: &mut App, task: iced::Task<Message>) {
    use iced::futures::StreamExt;
    let Some(stream) = iced_test::runtime::task::into_stream(task) else {
        return;
    };
    let produced: Vec<Message> = iced_test::futures::futures::executor::block_on(
        stream
            .filter_map(|action| async move {
                match action {
                    iced_test::runtime::Action::Output(m) => Some(m),
                    iced_test::runtime::Action::Image(
                        iced_test::runtime::image::Action::Allocate(_, response),
                    ) => {
                        let _ = response.send(Err(iced::widget::image::Error::Unsupported));
                        None
                    }
                    _ => None,
                }
            })
            .collect(),
    );
    for m in produced {
        send(a, m);
    }
}
