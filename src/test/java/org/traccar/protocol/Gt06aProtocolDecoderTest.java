package org.traccar.protocol;

import org.junit.jupiter.api.Test;
import org.traccar.ProtocolTest;
import org.traccar.model.Position;

public class Gt06aProtocolDecoderTest extends ProtocolTest {

    @Test
    public void testDecode() throws Exception {
//        tracker-server.log.20231208:2023-12-08 15:56:33  INFO: [Tbbdb57ad: gt06a < 223.104.81.13] 78780d0103539947110118220001f4320d0a
//        tracker-server.log.20231208:2023-12-08 15:56:33  INFO: [Tbbdb57ad] id: 353994711011822, time: 2023-12-08 15:55:40, lat: 23.16861, lon: 113.43501, speed: 0.5, course: 90.0
//        tracker-server.log.20231208:2023-12-08 15:56:34  INFO: [Tbbdb57ad: gt06a < 223.104.81.13] 79790020940a03539947110118220460045520305148898604351918420471480003c4980d0a
//        tracker-server.log.20231208:2023-12-08 15:56:34  INFO: [Tbbdb57ad] id: 353994711011822, time: 2023-12-08 15:55:40, lat: 23.16861, lon: 113.43501, speed: 0.5, course: 90.0
//        tracker-server.log.20231208:2023-12-08 16:02:44  INFO: [T396a5ef3: gt06a < 117.132.192.171] 78780d010353994711011822001968fb0d0a
//        tracker-server.log.20231208:2023-12-08 16:02:45  INFO: [T396a5ef3] id: 353994711011822, time: 2023-12-08 16:00:46, lat: 23.16862, lon: 113.43453, course: 90.0
        var decoder = inject(new Gt06aProtocolDecoder(null));

        verifyNull(decoder, binary(
                "78780d0103539947110118220001f4320d0a"));

        verifyNull(decoder, binary(
                "79790020940a03539947110118220460045520305148898604351918420471480003c4980d0a"));
        verifyAttribute(decoder, binary("78782112170b1e021537cd027c56850c2b946700d47a01cc000000000000050b12e68f7c0d0a"),
                Position.KEY_TYPE, String.valueOf(0x12));
        verifyAttribute(decoder, binary(
                        "78782112170b1e021537cd027c56850c2b946700d47a01cc000000000000050b12e68f7c0d0a"),
                "BAT_EXT", 12.91);

        verifyAttribute(decoder, binary(
                        "78782716170b1e031b2acd027c58b00c2b94520014ef0901cc00000000000050063c02020191005afd7c0d0a"),
                Position.KEY_TYPE, String.valueOf(0x16));
        verifyAttribute(decoder, binary("78782716170b1e031b2acd027c58b00c2b94520014ef0901cc00000000000050063c02020191005afd7c0d0a"),
                "BAT_EXT", 4.01);
    }

}
