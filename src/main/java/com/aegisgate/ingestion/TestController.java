package com.aegisgate.ingestion;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class TestController {

    private final KafkaProducerService kafkaProducerService;

    @GetMapping("/test-kafka")
    public String testKafka() {
        kafkaProducerService.sendDummyPayload();
        return "Message Sent to Kafka";
    }
}
