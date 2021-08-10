package com.hotelbeds.supplierintegrations.hackertest.detector.model;

import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 *
 * @author tony trabajo
 */
@Data
@AllArgsConstructor
@EqualsAndHashCode(of={"date"})
public class DetectorIpRegister {
    
    private final LocalDateTime date;
    
}
