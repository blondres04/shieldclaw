package com.aegisgate.audit;

import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class KafkaConsumerService {

    @KafkaListener(topics = "audit.pr.ingested", groupId = "aegis-group")
    public void consume(PRPayloadDTO payload) {
        log.info("Consumed PR payload: {}", payload);
    }
}
