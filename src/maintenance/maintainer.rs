use tokio_cron_scheduler::{Job, JobScheduler, JobSchedulerError};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct Maintainer {
    scheduler: Arc<Mutex<JobScheduler>>,
}

impl Maintainer {
    pub async fn new() -> Self {
        let scheduler = JobScheduler::new();
        Maintainer {
            scheduler: Arc::new(Mutex::new(scheduler)),
        }
    }

    // Method to add a job to the scheduler
    pub async fn schedule_task<F>(&self, task: F) -> Result<(), JobSchedulerError>
    where
        F: Fn() -> String + Send + Sync + Clone + 'static,
    {
        let job = Job::new_async("37 0 0 * * *", move |_uuid, _l| {
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

// Example task function
pub fn my_task(arg: &str) -> String {
    format!("Task executed with argument: {}", arg)
}

