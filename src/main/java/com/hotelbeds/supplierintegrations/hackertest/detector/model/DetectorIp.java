package com.hotelbeds.supplierintegrations.hackertest.detector.model;

import java.util.LinkedList;
import java.util.List;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.RequiredArgsConstructor;

/**
 *
 * @author tony trabajo
 */
@Data
@RequiredArgsConstructor
@EqualsAndHashCode(of={"ip"})
public class DetectorIp {
    
    private final String ip;       
    private final String username;
    
    private boolean bloqueado = false;       
    private List<DetectorIpRegister> listaRegistrosIP = new LinkedList<>();
    
}
