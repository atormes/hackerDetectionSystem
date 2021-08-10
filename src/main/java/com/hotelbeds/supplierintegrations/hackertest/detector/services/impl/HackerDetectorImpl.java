package com.hotelbeds.supplierintegrations.hackertest.detector.services.impl;

import com.hotelbeds.supplierintegrations.hackertest.detector.model.DetectorIp;
import com.hotelbeds.supplierintegrations.hackertest.detector.model.DetectorIpRegister;
import com.hotelbeds.supplierintegrations.hackertest.detector.services.HackerDetector;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

/**
 *
 * @author tony trabajo
 */
@Service
public class HackerDetectorImpl implements HackerDetector {

    private static final Logger log = Logger.getLogger(HackerDetectorImpl.class.getName());

    private static final int POSITION_IP = 0;
    private static final int POSITION_DATE = 1;
    private static final int POSITION_ACTION = 2;
    private static final int POSITION_USERNAME = 3;

    private static final String ACTION_OK = "SIGNIN_SUCCESS";
    private static final String ACTION_FAIL = "SIGNIN_FAILURE";

    private static final Pattern PATTERN = Pattern.compile("^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");

    private List<DetectorIp> ListDetectorIp;

    public boolean errorValidacion;
    public String mensajeValidacion;

    public HackerDetectorImpl() {
        errorValidacion = false;
        mensajeValidacion = "";
        ListDetectorIp = new LinkedList<>();

        try {
            FileHandler fileHandler = new FileHandler("\\logs\\HackerDetectionSystem_" + new SimpleDateFormat("yyyyMMdd_hh").format(new Date()) + ".log");
            fileHandler.setLevel(Level.INFO);
            log.addHandler(fileHandler);
            SimpleFormatter formatter = new SimpleFormatter();
            fileHandler.setFormatter(formatter);
        } catch (IOException ex) {
            log.warning("...WARNING: Los logs no se estan generando");
        }
    }

    public String parseLine(String line) {

        if (StringUtils.isBlank(line)) {
            log.severe("...ERROR: parseLine - Error la linea a parsear esta vacia");
            return null;
        }

        // parsear comando de log
        String[] parser = line.split(",");

        // Validacion de parser
        if (!validateParserLine(parser)) {
            log.severe("...ERROR: parseLine - Error en la validación de la línea parseada. " + this.mensajeValidacion);
            return null;
        }

        // nuevo objeto DetectorIp
        DetectorIp nuevaIp = new DetectorIp(parser[POSITION_IP], parser[POSITION_USERNAME]);
        DetectorIp ipEncontrada = null;

        //Date dateRegistro = new Date(Long.parseLong(parser[POSITION_DATE])*1000); //new Date(Long.parseLong(parser[POSITION_DATE]));
        //LocalDateTime fechaLocalDate = dateRegistro.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
        // Crear Objeto  DetectorIpRegister
        LocalDateTime fechaLocalDate = LocalDateTime.ofInstant(Instant.ofEpochMilli(Long.parseLong(parser[POSITION_DATE]) * 1000), ZoneId.systemDefault());
        DetectorIpRegister registroIp = new DetectorIpRegister(fechaLocalDate);

        //Comprobar si la acciones es FAILED
        if (ACTION_FAIL.equals(parser[POSITION_ACTION])) {

            //Evaluar si la IP esta ya añadida a ListDetectorIp        
            if (!ListDetectorIp.contains(nuevaIp)) {

                //Añadir objeto DetectorIpRegister a objeto nuevaIP
                log.info("parseLine - Se añade registro de la IP: " + nuevaIp.getIp() + " con fecha: " + registroIp.getDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd hh:mm:ss")));
                nuevaIp.getListaRegistrosIP().add(registroIp);

                // Añadir a la lista de ListDetectorIp
                log.info("parseLine - Se añade a la lista de IPDetected la IP: " + nuevaIp.getIp());
                ListDetectorIp.add(nuevaIp);

            } else {
                // Encontrar objeto Detector Ip con IP ya encontrada
                ipEncontrada = this.ListDetectorIp.get(this.ListDetectorIp.indexOf(nuevaIp));

                if (((ipEncontrada != null) && (!ipEncontrada.isBloqueado()))) {
                    log.info("parseLine - Se ha encontrado en la lista de IpDetected la IP: " + nuevaIp.getIp());
                    // Comprobar fecha objetos ListDetectorIp si son mayores de 5 minutos
                    int numRegistros = validateAndDeleteFechasListaRegisterIps(ipEncontrada, fechaLocalDate);

                    // Añadir objeto ListDetectorIpRegister
                    log.info("parseLine - Se añade registro de la IP: " + nuevaIp.getIp() + " con fecha: " + registroIp.getDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd hh:mm:ss")));
                    ipEncontrada.getListaRegistrosIP().add(registroIp);
                    log.info("parseLine - Número de registros detectados: " + ipEncontrada.getListaRegistrosIP().size() + " para la IP: " + nuevaIp.getIp());

                    // Se marca ip bloqueada para no añadir mas registros
                    if (ipEncontrada.getListaRegistrosIP().size() == 5) {
                        log.warning("...WARNING - parseLine - Se marca como BLOQUEADA la IP: " + nuevaIp.getIp() + " por excesos de reintentos: " + ipEncontrada.getListaRegistrosIP().size());
                        ipEncontrada.setBloqueado(true);
                        return nuevaIp.getIp();
                    }
                } else {
                    log.warning("...WARNING - parseLine - La IP: " + nuevaIp.getIp() + " se encuentra ya BLOQUEADA por excesos de reintentos");
                    this.errorValidacion = true;
                    this.mensajeValidacion = "La Ip se encuentra ya bloqueada por superar reintentos de conexión";
                    return nuevaIp.getIp();
                }
            }
        } else if (ACTION_OK.equals(parser[POSITION_ACTION])) {
            // Buscar si la IP esta ya registrada
            if(this.ListDetectorIp.indexOf(nuevaIp) >= 0){
                ipEncontrada = this.ListDetectorIp.get(this.ListDetectorIp.indexOf(nuevaIp));

                // Se comprueba que exita la IP en la lista y que no este marcada como BLOQUEADA
                if (((ipEncontrada != null) && (!ipEncontrada.isBloqueado()))) {
                    log.info("parseLine - Se elimina de la lista la IP: " + nuevaIp.getIp() + " al tener acción EXITOSA");
                    this.ListDetectorIp.remove(ipEncontrada);
                } else if (((ipEncontrada != null) && (ipEncontrada.isBloqueado()))) {
                    // Si la IP esta en estado BLOQUEADA -> se devuelve la IP como Ip detect hacker
                    log.warning("...WARNING: parseLine - La IP: " + nuevaIp.getIp() + " se encuentra BLOQUEADA. No se puede eliminar de la lista aun habiendo tenido acción EXITOSA");
                    return ipEncontrada.getIp();
                }
            }
        }
        // Devolver null
        return null;
    }

    public boolean validateParserLine(String[] data) {
        if (data.length != 4) {
            errorValidacion = true;
            mensajeValidacion = "Longitud de campos de parser incorrecto";
            return false;
        }

        if (!PATTERN.matcher(data[POSITION_IP]).matches()) {
            errorValidacion = true;
            mensajeValidacion = "Formato dato ip incorrecto";
            return false;
        }

        if (!StringUtils.isNumeric(data[POSITION_DATE])) {
            errorValidacion = true;
            mensajeValidacion = "Formato dato Fecha incorrecto";
            return false;
        }
        if (!((ACTION_OK.equals(data[POSITION_ACTION])) || (ACTION_FAIL.equals(data[POSITION_ACTION])))) {
            errorValidacion = true;
            mensajeValidacion = "Valor dato Action incorrecto";
            return false;
        }

        if (StringUtils.isBlank(data[POSITION_USERNAME])) {
            errorValidacion = true;
            mensajeValidacion = "Valor dato UserName incorrecto";
            return false;
        }
        return true;
    }

    public int validateAndDeleteFechasListaRegisterIps(DetectorIp ipEncontrada, LocalDateTime fechaNueva) {
        for (int i = 0; i < ipEncontrada.getListaRegistrosIP().size(); i++) {
            // Comprobar si la fecha de la lista es anterior a la fechaNueva menos 5 minutos para borrarla
            if (ipEncontrada.getListaRegistrosIP().get(i).getDate().isBefore(fechaNueva.minusMinutes(5))) {
                log.info("validateAndDeleteFechasListaRegisterIps - Se elimina el registro con fecha: " + ipEncontrada.getListaRegistrosIP().get(i).getDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd hh:mm:ss")) + "  de la IP: " + ipEncontrada.getIp() + ", porque la fecha del registro actual es: " + fechaNueva.format(DateTimeFormatter.ofPattern("yyyy-MM-dd hh:mm:ss")));
                ipEncontrada.getListaRegistrosIP().remove(new DetectorIpRegister(ipEncontrada.getListaRegistrosIP().get(i).getDate()));
            }
        }
        return ipEncontrada.getListaRegistrosIP().size();
    }

    public void clearListDetectorIp() {
        this.ListDetectorIp.clear();
    }

    public void printListDetectorIp() {
        if (this.ListDetectorIp.size() == 0) {
            System.out.println("La lista de IPs detectadas como erroneas esta todavia vacia");
        } else {
            System.out.println("Lita de Ips detectadas como fallo de LOGIN");
            System.out.println("------------------------------------------");
            // Listar el contenido de la lista IP detectadas
            for (DetectorIp ip : this.ListDetectorIp) {
                System.out.println("IP Detectada fallo de Login: " + ip.toString());
                System.out.println("Fallos detectados ip: " + ip.getIp());
                System.out.println("---------------------");
                int i = 0;
                for (DetectorIpRegister registroFalloIP : ip.getListaRegistrosIP()) {
                    i++;
                    System.out.println("Fallo " + i + ": " + registroFalloIP.toString());
                }
            }
        }
    }

    public boolean isErrorValidacion() {
        return errorValidacion;
    }

    public String getMensajeValidacion() {
        return mensajeValidacion;
    }

}
