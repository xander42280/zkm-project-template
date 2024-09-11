use std::sync::{Arc, Mutex};
use std::thread;
use std::collections::HashMap;
use std::time::Duration;

pub struct ProverTask {
    is_done: bool,
}

impl Task {
    fn new() -> Task {
        Task { is_done: false }
    }

    fn run(&mut self) {
        // 模拟任务运行时间
        thread::sleep(Duration::from_secs(5));
        self.is_done = true;
    }

    fn is_done(&self) -> bool {
        self.is_done
    }
}

pub struct LocalProver {
    tasks: Arc<Mutex<HashMap<String, Arc<Mutex<Task>>>>>,
}

#[async_trait]
impl Prover for LocalProver {
    async fn request_proof<'a>(&self, input: &'a ProverInput) -> anyhow::Result<String> {
        let proof_id = uuid::Uuid::new_v4().to_string();
        // start a new thread generate proof

        Ok(response.proof_id)
    }

    async fn wait_proof<'a>(
        &self,
        proof_id: &'a str,
        timeout: Option<Duration>,
    ) -> anyhow::Result<Option<ProverResult>> {
        let start_time = Instant::now();
        let mut client = self.stage_client.clone();
        loop {
            if let Some(timeout) = timeout {
                if start_time.elapsed() > timeout {
                    return Err(anyhow::anyhow!("Proof generation timed out."));
                }
            }

            let get_status_request = GetStatusRequest {
                proof_id: proof_id.to_string(),
            };
            let get_status_response = client.get_status(get_status_request).await?.into_inner();

            match Status::from_i32(get_status_response.status as i32) {
                Some(Status::Computing) => {
                    log::debug!("generate_proof step: {}", get_status_response.step);
                    sleep(Duration::from_secs(2)).await;
                }
                Some(Status::Success) => {
                    let stark_proof =
                        NetworkProver::download_file(&get_status_response.stark_proof_url).await?;
                    let solidity_verifier =
                        NetworkProver::download_file(&get_status_response.solidity_verifier_url)
                            .await?;
                    let proof_result = ProverResult {
                        output_stream: get_status_response.output_stream,
                        proof_with_public_inputs: get_status_response.proof_with_public_inputs,
                        stark_proof,
                        solidity_verifier,
                    };
                    return Ok(Some(proof_result));
                }
                _ => {
                    log::error!(
                        "generate_proof failed status: {}",
                        get_status_response.status
                    );
                    return Ok(None);
                }
            }
        }
    }

    async fn prover<'a>(
        &self,
        input: &'a ProverInput,
        timeout: Option<Duration>,
    ) -> anyhow::Result<Option<ProverResult>> {
        let proof_id = self.request_proof(input).await?;
        self.wait_proof(&proof_id, timeout).await
    }
}