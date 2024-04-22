#[derive(Debug)]
pub(crate) struct Updater<E> {
    stop_signal: std::sync::Arc<std::sync::RwLock<bool>>,
    phantom: std::marker::PhantomData<E>,
}

impl<E> Drop for Updater<E> {
    /// Ensure the update thread is getting ended when dropping reference to main object.
    /// The main object is the only mean to access data produced by the update thread.
    fn drop(&mut self) {
        let mut stop_signal = self.stop_signal.write().unwrap();
        *stop_signal = true;
        log::trace!("Ending update thread...");
    }
}

impl<E> Clone for Updater<E> {
    fn clone(&self) -> Self {
        Self {
            stop_signal: self.stop_signal.clone(),
            phantom: std::marker::PhantomData,
        }
    }
}

enum UpdaterRunReturn {
    /// Just run another iteration
    Continue,
    /// End running updater (e.g. due to stop signal)
    End,
}

impl<E> Updater<E>
where
    E: std::error::Error,
{
    pub fn new(
        get_next_update_time: impl Fn() -> Result<Option<chrono::DateTime<chrono::Utc>>, E>
            + std::marker::Send
            + 'static,
        do_update: impl Fn() -> Result<(), E> + std::marker::Send + 'static,
    ) -> Self {
        // create a new Arc and RwLock to not stop our new thread
        let stop_signal = std::sync::Arc::new(std::sync::RwLock::new(false));

        let update_thread_stop = stop_signal.clone();
        std::thread::spawn(move || {
            loop {
                let update_result = (|| -> Result<UpdaterRunReturn, E> {
                    let next_refresh_opt = get_next_update_time()?;
                    if let Some(next_refresh) = next_refresh_opt {
                        let diff = next_refresh.time() - chrono::offset::Utc::now().time();
                        if diff
                            > chrono::Duration::new(0, 0).expect("Unable to construct time delta1")
                        {
                            log::trace!("Update thread sleeping for {:?}", diff);
                            std::thread::sleep(
                                diff.to_std().expect(
                                    "Unable to fit chrono::Duration into std::time::duration",
                                ),
                            );
                        } else {
                            // duration is negative, just continue
                            log::warn!("Received negative duration from get_next_update_time. Maybe you selected a bad refresh strategy? You might want select a refresh strategy, which is returning timestamps with at least a few seconds in the future to prevent DoSing");
                            // make sure we are not running in endless loop
                            std::thread::sleep(std::time::Duration::new(1, 0));
                        }
                    } else {
                        log::info!("Exiting refresh thread as refresh policy does not request any refresh in future.");
                        return Ok(UpdaterRunReturn::End);
                    }

                    // break condition
                    if *update_thread_stop.read().unwrap() {
                        log::trace!("Exiting refresh thread as requested by stop signal.");
                        return Ok(UpdaterRunReturn::End);
                    }

                    do_update()?;

                    Ok(UpdaterRunReturn::Continue)
                })();
                match update_result {
                    Ok(res) => match res {
                        UpdaterRunReturn::Continue => {}
                        UpdaterRunReturn::End => break,
                    },
                    Err(error) => log::error!("Updating data failed with {:?}", error),
                }
            }
        });

        Self {
            stop_signal,
            phantom: std::marker::PhantomData,
        }
    }
}
