// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.junit.jupiter.api.Test;

public class StreamDumpTest {

    private static InputStream stringToStream(String string) throws IOException {
        return new ArmoredInputStream(new ByteArrayInputStream(string.getBytes(Charset.forName("UTF8"))));
    }

    private static void printDataName(String name) {
        // CHECKSTYLE:OFF
        System.out.println("##############################################");
        System.out.println(name);
        System.out.println("##############################################");
        // CHECKSTYLE:ON
    }

    @Test
    public void dumpSecretKey() throws IOException, PGPException {
        String data = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "lFgEWx6DORYJKwYBBAHaRw8BAQdABJa6xH6/nQoBQtVuqaenNLrKvkJ5gniGtBH3\n" +
                "tsK+ckkAAP9uxXBqYoH/Kh+rjNMKRO6pgdkoYTYvMh5TVcQHR6LzoA+ttCxFbW1l\n" +
                "bGllIERvcm90aGVhIERpbmEgU2FtYW50aGEgQXdpbmEgRWQyNTUxOYiQBBMWCAA4\n" +
                "FiEEjowz+kYmM3l22Xl4BpwMNI3YLBkFAlsegzkCGwMFCwkIBwIGFQoJCAsCBBYC\n" +
                "AwECHgECF4AACgkQBpwMNI3YLBlo5wD7B2CyTh/hEQOaZV56TqRpabY+zpCs2cTX\n" +
                "7IjZnkEi5OAA/0WxAICvyJBkKIittgbnyQXml1UysgZ/Vv0dzNb+UgsPnFgEW4PY\n" +
                "rxYJKwYBBAHaRw8BAQdA0LwoloQu+RTjYydL+2Qp/dmmY13fFUG72tEw3JTsJr8A\n" +
                "AQCGQqw6/M3duPYNiNxo3D1w2XW1j1IJPm3+Zxb1bxDCHhDMiO8EGBYIACAWIQSO\n" +
                "jDP6RiYzeXbZeXgGnAw0jdgsGQUCW4PYrwIbAgCBCRAGnAw0jdgsGXYgBBkWCAAd\n" +
                "FiEEBhw8pEr/DsWNxm6VIuP6/pa1bDIFAluD2K8ACgkQIuP6/pa1bDJoTQD/cYH2\n" +
                "EFRBljjnT6DiPJYEJRoz5IAXgnKaOntXPA/9uCYBAN8po38vE9auBLpOM8QKNVIS\n" +
                "CGG3Y2bOe2BIQ8K25bkKJ4ABAN1KMV+Lb5Bdgh1xMvjGILyT+aVH3dIppj/mBlnH\n" +
                "O3mrAP9RgDT1iuvJlwIaML8Hq/uaG1Ryd9rwfAt0tfqj0dY1Cw==\n" +
                "=HYsE\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";

        printDataName("Secret Key");
        InputStream inputStream = stringToStream(data);
        StreamDumper.dump(inputStream, null, System.out);
    }

    @Test
    public void dumpEncryptedMessage() throws IOException, PGPException {
        String data = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wV4Di9iOlMDSAzMSAQdAu/2VmD0uZASFHqAD0IVNq7C8rdsJ+ZQd2nQsuBilygUw\n" +
                "9bK+bOzU6ksTZgKgdAjO8zpvM+N0B3L0TtiwLr5rj0rPkCyVLdACnBpWOCZCMpsK\n" +
                "0j4B4um24+oCDHtxRu1e1IvsboBtGN9ElxidGAiUdPJ3L0QrNVgzdmVTwuywtIHW\n" +
                "r66Eaq8vCTmJpcsy0BYTiQ==\n" +
                "=FY/Q\n" +
                "-----END PGP MESSAGE-----\n";

        printDataName("Encrypted Message");
        InputStream inputStream = stringToStream(data);
        StreamDumper.dump(inputStream, null, System.out);
    }

    @Test
    public void dumpEncryptedMessage_withSessionKey() throws PGPException, IOException {
        String data = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wV4Di9iOlMDSAzMSAQdAu/2VmD0uZASFHqAD0IVNq7C8rdsJ+ZQd2nQsuBilygUw\n" +
                "9bK+bOzU6ksTZgKgdAjO8zpvM+N0B3L0TtiwLr5rj0rPkCyVLdACnBpWOCZCMpsK\n" +
                "0j4B4um24+oCDHtxRu1e1IvsboBtGN9ElxidGAiUdPJ3L0QrNVgzdmVTwuywtIHW\n" +
                "r66Eaq8vCTmJpcsy0BYTiQ==\n" +
                "=FY/Q\n" +
                "-----END PGP MESSAGE-----\n";
        PGPSessionKey sessionKey = PGPSessionKey
                .fromAsciiRepresentation("9:920B1779565C8DF4DD9DB46966CDF2B51BC882C241DE8EF437CADEC711E7EB04");

        printDataName("Encrypted Message (with Session Key)");
        InputStream inputStream = stringToStream(data);
        StreamDumper.dump(inputStream, sessionKey, System.out);
    }

    @Test
    public void dumpEncryptedMessage_withWrongSessionKey() throws PGPException, IOException {
        String data = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wV4Di9iOlMDSAzMSAQdAu/2VmD0uZASFHqAD0IVNq7C8rdsJ+ZQd2nQsuBilygUw\n" +
                "9bK+bOzU6ksTZgKgdAjO8zpvM+N0B3L0TtiwLr5rj0rPkCyVLdACnBpWOCZCMpsK\n" +
                "0j4B4um24+oCDHtxRu1e1IvsboBtGN9ElxidGAiUdPJ3L0QrNVgzdmVTwuywtIHW\n" +
                "r66Eaq8vCTmJpcsy0BYTiQ==\n" +
                "=FY/Q\n" +
                "-----END PGP MESSAGE-----\n";
        PGPSessionKey sessionKey = PGPSessionKey
                .fromAsciiRepresentation("9:920B1779565C8DF4DD9DB46966CDF2B51BC882C241DE8EF437CADEC711E7EBFF");

        printDataName("Encrypted Message (with Wrong Session Key)");
        InputStream inputStream = stringToStream(data);
        StreamDumper.dump(inputStream, sessionKey, System.out);
    }

    @Test
    public void dumpEncryptedMessageForTwoRecipients() throws PGPException, IOException {
        String data = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wV4Di9iOlMDSAzMSAQdAALX6636VfMV+kljW5l6AfcRtnp9RpCO7GG/UrMhpKCgw\n" +
                "sx1mBvZsfw6y0MUJgNoOHjAlFhxl7SgjH+hVxCs1EjV+BiFm5XcH0Sz3x0AmT4Ev\n" +
                "wcBMA0niEYFmySYyAQf/a3QjVA5qxQhD/22JGkvt0EsnOebIEKoA4IqUm0bHOfzH\n" +
                "yiolVp2e8TDGTGDfuPGZe7kWACN5xMshoinSOw5vlGl0OYQt5kqO9ihk8SUtFz/n\n" +
                "zpjP4R8g5XfHQ6A8aTm7XzjcYiImYJcanvqsPz1oVbXUFjgjWP+IdbGEH2+oahrO\n" +
                "TYTkaIIFSPENjhwhELA5J6whdYIGPAd4Flqa885Bwq7/mJtizGSUqfMm/vy9Ynyv\n" +
                "PM9gO44U6f5WNJjVORAAvGRs+yNoDemOR+Tk5lhq69gUysRbTDFKvalAnIg+jDCs\n" +
                "gov/OsSifJfMJpfkp6B/eq1g3VUxXfXMH9JlpUI1r9I+Ac9cg2nmvMJEYndoeinS\n" +
                "pXaFOPETcoKe502lXn5nb03sGMBD8jRXd1RiFvvB3emqIczBe1r4a7ntVfDp5Hs=\n" +
                "=QCSD\n" +
                "-----END PGP MESSAGE-----\n";
        PGPSessionKey sessionKey = PGPSessionKey
                .fromAsciiRepresentation("9:092F816748B2C6FCA49130E931F9DDCF46E4106CE3C4A8437AB660E0C6FED0A1");

        printDataName("Encrypted Message for Two Recipients");
        InputStream inputStream = stringToStream(data);
        StreamDumper.dump(inputStream, sessionKey, System.out);
    }

    @Test
    public void dumpSignedMessage() throws PGPException, IOException {
        String data = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "xA0DAAgB0D9vhlIm/osBxA0DAAoWCTXiD9yZ2YYByxRiAAAAAABIZWxsbywgd29y\n" +
                "bGQhCsJ1BAAWCgAnBYJcdpUyFiEEjeZMrRdY/BlFYM9ZCTXiD9yZ2YYJEAk14g/c\n" +
                "mdmGAAC5AgD/U/FD8PPqqABrkdg9bV4aToP6YENgXGq8M7SIvTaznl0BAM1KdOKs\n" +
                "UWPQgh5AJp3kOUzSO7v+brfw03O1wQaOmgsHwsBzBAABCAAnBYJdkKU/FiEEPoh3\n" +
                "yHcnRpKXUYn10D9vhlIm/osJENA/b4ZSJv6LAAAQ1Qf/bC4uL61DQrR0s+3n7By8\n" +
                "Rp0cfppfR94NK9GUtCcL03Ci78qimpjcZja+r03xTj4r3TGASRngaYD0cOU+erF9\n" +
                "DO3PPGZKxajOqtFXoQKdQnUhaRnU2CMfL+voRzH7kFssvcHzy7JoeFDLxadt8yym\n" +
                "Hm3vN+oDB3b8uWVEzaVMn71cbjJzlsLBaLclSlE/Nj36x9TeunnHhZJ7BFmkTaBd\n" +
                "W5kdBtqIV6Mii+xiYjrtrkFzYkEDNz6hK2so8SjpaGck2tSiBSrybf0/CLWwb/+e\n" +
                "i6yLPi6Afbxz+5Yp4jjxNkUdjeQFNFExix0DUPVowhZQN9hwZvJXmfUzi71+BB6N\n" +
                "uA==\n" +
                "=BDwS\n" +
                "-----END PGP MESSAGE-----\n";

        printDataName("Signed Message");
        InputStream inputStream = stringToStream(data);
        StreamDumper.dump(inputStream, null, System.out);
    }

    @Test
    public void dumpSignedCompressedMessage() throws PGPException, IOException {
        String data = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "owGbwMvMwCH2sPOSUOzzWymMp0WSGGK6InU9UnNy8nUUyvOLclIUuTpKWRjEOBhk\n" +
                "xRRZ8jZHv1c9Zfp0SurkSJguViaQFgYuTgGYSJ09w/8M9xn6J9em8Bvs3rHgYd+G\n" +
                "z519Zy++FFuYsPHwz8KmXNliRoaNP2zq+A5kp7MJWjc2JrdXW8y+GTd9So2lDcMq\n" +
                "h3UsTFwA\n" +
                "=56Gw\n" +
                "-----END PGP MESSAGE-----";

        printDataName("Signed Compressed Data");
        InputStream inputStream = stringToStream(data);
        StreamDumper.dump(inputStream, null, System.out);
    }
}
