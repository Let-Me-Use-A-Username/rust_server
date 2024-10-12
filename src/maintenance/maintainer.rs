use tokio_cron_scheduler::{Job, JobScheduler, JobSchedulerError};
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as TokioMutex;

use crate::database::handler::DatabaseHandler;

pub struct Maintainer {
    scheduler: Arc<TokioMutex<JobScheduler>>,
}

impl Maintainer {
    pub async fn new() -> Self {
        let scheduler = JobScheduler::new();
        Maintainer {
            scheduler: Arc::new(TokioMutex::new(scheduler)),
        }
    }

    // Method to add a job to the scheduler
    pub async fn schedule_task<F>(&self, task: F) -> Result<(), JobSchedulerError>
    where
        F: Fn() -> String + Send + Sync + Clone + 'static,
    {
        //FIXME : Correct the interval
        let job = Job::new_async("* * * * * *", move |_uuid, _l| {
            let task = task.clone();
            Box::pin(async move {
                let result = task();
                println!("Task executed at midnight: {}", result);
            })
        })
        .unwrap();

        let mut scheduler = self.scheduler.lock().await;
        return scheduler.add(job);
    }

    // Start the scheduler
    pub async fn start(&self) {
        let scheduler = self.scheduler.lock().await;
        if let Err(e) = scheduler.start().await{
            eprintln!("Error on scheduler {:?}", e);
        }
    }
}

///Guest session cleanup function.
pub fn guest_cleanup(handler_op: Arc<Mutex<DatabaseHandler>>) -> String {
    let handler = handler_op.lock().unwrap();
    
    return "".to_string()
}

