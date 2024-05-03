#[derive(Debug)]
pub(crate) struct Updater<E> {
    cancellation_token: tokio_util::sync::CancellationToken,
    #[cfg(not(target_arch = "wasm32"))]
    join_handle: std::sync::Arc<tokio::task::JoinHandle<()>>,
    phantom_e: std::marker::PhantomData<E>,
}

impl<E> Drop for Updater<E> {
    /// Ensure the update thread is getting ended when dropping reference to main object.
    /// The main object is the only mean to access data produced by the update thread.
    fn drop(&mut self) {
        self.cancellation_token.cancel();
        #[cfg(not(target_arch = "wasm32"))]
        self.join_handle.abort();
        log::trace!("Requested to end update thread...");
    }
}

enum UpdaterRunReturn {
    /// Just run another iteration
    Continue,
    /// End running updater (e.g. due to stop signal)
    End,
}

pub trait UpdaterImpl<E>
where
    E: std::error::Error,
{
    #[cfg(target_arch = "wasm32")]
    fn get_next_update_time(
        &self,
    ) -> impl std::future::Future<Output = Result<Option<chrono::DateTime<chrono::Utc>>, E>>;

    #[cfg(not(target_arch = "wasm32"))]
    fn get_next_update_time(
        &self,
    ) -> impl std::future::Future<Output = Result<Option<chrono::DateTime<chrono::Utc>>, E>> + Send;

    #[cfg(target_arch = "wasm32")]
    fn do_update(&self) -> impl std::future::Future<Output = Result<(), E>>;

    #[cfg(not(target_arch = "wasm32"))]
    fn do_update(&self) -> impl std::future::Future<Output = Result<(), E>> + Send;
}

impl<E> Updater<E>
where
    E: std::error::Error + 'static,
{
    pub fn new<U>(updater: U) -> Self
    where
        U: UpdaterImpl<E> + Send + Sync + Clone + 'static,
    {
        let cancellation_token = tokio_util::sync::CancellationToken::new();
        let cancellation_token_task = cancellation_token.clone();

        let updater_future = async move {
            loop {
                let update_result: Result<UpdaterRunReturn, Box<dyn std::error::Error + 'static>> = (async {
                    let next_refresh_opt = updater.get_next_update_time().await?;
                    if let Some(next_refresh) = next_refresh_opt {
                        let diff = next_refresh.time() - chrono::offset::Utc::now().time();
                        if diff
                            > chrono::Duration::new(0, 0).expect("Unable to construct time delta1")
                        {
                            log::trace!("Update thread sleeping for {:?}", diff);
                            #[cfg(not(target_arch = "wasm32"))]
                            tokio::time::sleep(
                                diff.to_std().expect(
                                    "Unable to fit chrono::Duration into std::time::duration",
                                ),
                            ).await;
                            #[cfg(target_arch = "wasm32")]
                            gloo_timers::future::TimeoutFuture::new(diff.num_milliseconds().try_into().unwrap()).await;
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

                    // check if we are requested to exit
                    if cancellation_token_task.is_cancelled() {
                        log::trace!("Ending update task as cancellation token is requesting it...");
                        return Ok(UpdaterRunReturn::End);
                    }

                    updater.do_update().await?;

                    Ok(UpdaterRunReturn::Continue)
                }).await;
                match update_result {
                    Ok(res) => match res {
                        UpdaterRunReturn::Continue => {}
                        UpdaterRunReturn::End => break,
                    },
                    Err(error) => {
                        // Suppress error when cancellation token is set and the network request gets possibly interrupted.
                        // This could happen if the task abort is scheduled during a reqwest request.
                        // This causes a `Custom { kind: Interrupted, error: JoinError::Cancelled(Id(17)) }`, which does not implement
                        // `source` so we cannot check for it...
                        if !cancellation_token_task.is_cancelled() {
                            log::error!("Updating data failed with {:#?}", error);
                        }
                    }
                }
            }
        };

        #[cfg(not(target_arch = "wasm32"))]
        let join_handle = tokio::spawn(updater_future).into();

        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(updater_future);

        Self {
            cancellation_token,
            #[cfg(not(target_arch = "wasm32"))]
            join_handle,
            phantom_e: std::marker::PhantomData,
        }
    }
}
