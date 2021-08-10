package com.hotelbeds.supplierintegrations.hackerDetects.detector.tests;

import com.hotelbeds.supplierintegrations.hackertest.detector.Configurator.SpringConfiguration;
import com.hotelbeds.supplierintegrations.hackertest.detector.model.DetectorIp;
import com.hotelbeds.supplierintegrations.hackertest.detector.services.impl.HackerDetectorImpl;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.springframework.context.annotation.AnnotationConfigApplicationContext;

/**
 *
 * @author Tony trabajo
 */
public class TestHackerDetectorImpl {

    private static final Logger log = Logger.getLogger(TestHackerDetectorImpl.class.getName());
    private static HackerDetectorImpl hackerDetectorImpl;

    @BeforeClass
    public static void init_TestHackerDetectorImpl() {
        // Recoger el bean de HackerDetectorImpl desde el contexto de configuracion de la aplicacion SPRING
        AnnotationConfigApplicationContext contexto = new AnnotationConfigApplicationContext();
        contexto.register(SpringConfiguration.class);
        contexto.refresh();
        hackerDetectorImpl = contexto.getBean(HackerDetectorImpl.class);

        // Derivar log a un fichero en carpeta ..\logs
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

    @Before
    public void InicializarTests() {
        hackerDetectorImpl.clearListDetectorIp();
    }

    @Test
    public void testValidateParserLine() {
        //Linea CORRECTA
        boolean returnLineOk = hackerDetectorImpl.validateParserLine("192.168.15.3,1628442847,SIGNIN_SUCCESS,antonio".split(","));
        assertTrue("Linea incorrecta" + hackerDetectorImpl.getMensajeValidacion(), returnLineOk);

        //Linea KO - iP INVALIDA
        boolean retunrLineKoIp = hackerDetectorImpl.validateParserLine(".168.as.s,1628442847,SIGNIN_SUCCESS,antonio".split(","));
        assertFalse("Linea incorrecta. " + hackerDetectorImpl.getMensajeValidacion(), retunrLineKoIp);

        //Linea KO - Fecha INVALIDA
        boolean returnLineKoDate = hackerDetectorImpl.validateParserLine("192.168.15.1,asdf,SIGNIN_SUCCESS,antonio".split(","));
        assertFalse("Linea incorrecta. " + hackerDetectorImpl.getMensajeValidacion(), returnLineKoDate);

        //Linea KO - Action INVALIDA
        boolean returnLineKoAction = hackerDetectorImpl.validateParserLine("192.168.15.1,1628442847,SI_FAILURE,antonio".split(","));
        assertFalse("Linea incorrecta. " + hackerDetectorImpl.getMensajeValidacion(), returnLineKoAction);

        //Linea KO - username INVALIDA
        boolean returnLineKoUsername = hackerDetectorImpl.validateParserLine("192.168.15.1,1628442847,SIGNIN_SUCCESS,".split(","));
        assertFalse("Linea incorrecta. " + hackerDetectorImpl.getMensajeValidacion(), returnLineKoUsername);
    }

    @Test
    public void testValidateAndDeleteFechasListaRegisterIps() {
        String ipHackedReturn = hackerDetectorImpl.parseLine("192.168.15.1,1628442847,SIGNIN_FAILURE,antonio");
        int numero = hackerDetectorImpl.validateAndDeleteFechasListaRegisterIps(new DetectorIp("192.168.15.1", "antonio"), LocalDateTime.now());
        assertTrue("ValidateAndDeleteFechasListaRegisterIps SUCCESS. Se elimino el registro existente para la IP", numero == 0);
    }

    @Test
    public void testParseLineLoginActionSuccess() {
        String ipHackedReturn = hackerDetectorImpl.parseLine("192.168.15.2,1628442847,SIGNIN_SUCCESS,antonio");
        assertNull("Parse Line SUCCESS. Exito de login", ipHackedReturn);
    }

    @Test
    public void testParseLineLoginOneFailed() {
        String ipHackedReturn = hackerDetectorImpl.parseLine("192.168.15.3,1628442847,SIGNIN_FAILURE,antonio");
        ipHackedReturn = hackerDetectorImpl.parseLine("192.168.15.3,1628442857,SIGNIN_SUCCESS,antonio");
        assertNull("Parse Line SUCCESS. Exito de login", ipHackedReturn);
    }

    @Test
    public void testParseLineHackedLogin() {
        //Demas Intentos fallidos - Detecter Hacker
        String ipHackedReturn = hackerDetectorImpl.parseLine("192.168.15.4,1628442847,SIGNIN_FAILURE,antonio");
        ipHackedReturn = hackerDetectorImpl.parseLine("192.168.15.4,1628442907,SIGNIN_FAILURE,antonio");
        ipHackedReturn = hackerDetectorImpl.parseLine("192.168.15.4,1628442967,SIGNIN_FAILURE,antonio");
        ipHackedReturn = hackerDetectorImpl.parseLine("192.168.15.4,1628443027,SIGNIN_FAILURE,antonio");
        ipHackedReturn = hackerDetectorImpl.parseLine("192.168.15.4,1628443047,SIGNIN_FAILURE,antonio");
        assertNotNull("Parse Line FAILED. Intento de Hackeo del sistema", ipHackedReturn);
    }

    @Test
    public void testParseLineIpYaBloqueada() {
        String ipHackedReturn = hackerDetectorImpl.parseLine("192.168.15.5,1628442847,SIGNIN_FAILURE,antonio");
        ipHackedReturn = hackerDetectorImpl.parseLine("192.168.15.5,1628442907,SIGNIN_FAILURE,antonio");
        ipHackedReturn = hackerDetectorImpl.parseLine("192.168.15.5,1628442967,SIGNIN_FAILURE,antonio");
        ipHackedReturn = hackerDetectorImpl.parseLine("192.168.15.5,1628443027,SIGNIN_FAILURE,antonio");
        ipHackedReturn = hackerDetectorImpl.parseLine("192.168.15.5,1628443047,SIGNIN_FAILURE,antonio");
        
        //Primer Intento FAILURE  - Se reintenta la IP bBLOQUEADA en el test anterior
        ipHackedReturn = hackerDetectorImpl.parseLine("192.168.15.5,1628442887,SIGNIN_FAILURE,antonio");
        assertNotNull("Parse Line FAILED. Intento de Hackeo del sistema. " + hackerDetectorImpl.getMensajeValidacion(), ipHackedReturn);
    }

    @After
    public void finalizarTests() {
        // Imprimir estado de la lista de IPs detectadas
        hackerDetectorImpl.printListDetectorIp();
    }

}
