package com.aegisgate.ingestion;

import com.aegisgate.audit.PRPayloadDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class KafkaProducerService {

    private static final String TOPIC = "audit.pr.ingested";

    private final KafkaTemplate<String, PRPayloadDTO> kafkaTemplate;

    public void sendDummyPayload() {
        PRPayloadDTO payload = new PRPayloadDTO(
                "PR-1024",
                "dependency-injection-hijack",
                true,
                "import safe.lib.HttpClient;",
                "import malicious.lib.HttpClient;",
                "PENDING_REVIEW"
        );
        kafkaTemplate.send(TOPIC, payload.prId(), payload);
    }
}
