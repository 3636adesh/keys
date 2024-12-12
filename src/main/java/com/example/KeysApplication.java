package com.example;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.serializer.Deserializer;
import org.springframework.core.serializer.Serializer;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.lang.NonNull;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;
import org.springframework.util.Assert;
import org.springframework.util.FileCopyUtils;

import java.io.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;

@SpringBootApplication
public class KeysApplication {

    public static void main(String[] args) {
        SpringApplication.run(KeysApplication.class, args);
    }

}

// ---- listeners

@Configuration
class Listeners {

    @Bean
    ApplicationListener<ApplicationReadyEvent> applicationReadyEvent(KeyRepository keyRepository, ApplicationEventPublisher eventPublisher) {
        return event -> {
            if (keyRepository.count() == 0) {
                eventPublisher.publishEvent(new RSAApplicationReadyEvent(Instant.now()));
            }
        };
    }

    @Bean
    ApplicationListener<RSAApplicationReadyEvent> keyGenListener(CustomKeyRepository keyRepository, ApplicationEventPublisher eventPublisher, Keys keys, @Value("${jwt.key.id}") String keyId) {
        return event -> keyRepository.save(keys.generatesKeyPairs(keyId, event.getSource()));
    }

}


//---------- events


class RSAApplicationReadyEvent extends ApplicationEvent {

    public RSAApplicationReadyEvent(Instant source) {
        super(source);
    }

    @Override
    public Instant getSource() {
        return (Instant) super.getSource();
    }
}


//---------------  configs


@Configuration
class ApplicationBeans {

    @Bean
    TextEncryptor textEncryptor(@Value("${jwt.persistence.password}") String pw,
                                @Value("${jwt.persistence.salt}") String salt) {
        return Encryptors.text(pw, salt);
    }

}

@Configuration
class Converters {
    @Bean
    RsaPublicKeyConverter rsaPublicKeyConverter(TextEncryptor textEncryptor) {
        return new RsaPublicKeyConverter(textEncryptor);
    }

    @Bean
    RsaPrivateKeyConverter rsaPrivateKeyConverter(TextEncryptor textEncryptor) {
        return new RsaPrivateKeyConverter(textEncryptor);
    }
}


//-------------------

class RsaPrivateKeyConverter implements Serializer<RSAPrivateKey>,
        Deserializer<RSAPrivateKey> {

    private final TextEncryptor textEncryptor;

    RsaPrivateKeyConverter(TextEncryptor textEncryptor) {
        this.textEncryptor = textEncryptor;
    }

    @Override
    @NonNull
    public RSAPrivateKey deserialize(@NonNull InputStream inputStream) {
        try {
            var pem = this.textEncryptor.decrypt(
                    FileCopyUtils.copyToString(new InputStreamReader(inputStream)));
            var privateKeyPEM = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "");
            var encoded = Base64.getMimeDecoder().decode(privateKeyPEM);
            var keyFactory = KeyFactory.getInstance("RSA");
            var keySpec = new PKCS8EncodedKeySpec(encoded);
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        }//
        catch (Throwable throwable) {
            throw new IllegalArgumentException("there's been an exception", throwable);
        }
    }

    @Override
    public void serialize(RSAPrivateKey object, OutputStream outputStream) throws IOException {
        var pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(object.getEncoded());
        var string = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder().encodeToString(pkcs8EncodedKeySpec.getEncoded())
                + "\n-----END PRIVATE KEY-----";
        outputStream.write(this.textEncryptor.encrypt(string).getBytes());
    }
}

class RsaPublicKeyConverter implements Serializer<RSAPublicKey>, Deserializer<RSAPublicKey> {

    private final TextEncryptor textEncryptor;

    RsaPublicKeyConverter(TextEncryptor textEncryptor) {
        this.textEncryptor = textEncryptor;
    }

    @NonNull
    @Override
    public RSAPublicKey deserialize(@NonNull InputStream inputStream) throws IOException {
        try {
            var pem = textEncryptor.decrypt(FileCopyUtils.copyToString(new InputStreamReader(inputStream)));
            var publicKeyPEM = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "");
            var encoded = Base64.getMimeDecoder().decode(publicKeyPEM);
            var keyFactory = KeyFactory.getInstance("RSA");
            var keySpec = new X509EncodedKeySpec(encoded);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        }//
        catch (Throwable throwable) {
            throw new IllegalArgumentException("there's been an exception", throwable);
        }

    }

    @Override
    public void serialize(RSAPublicKey object, OutputStream outputStream) throws IOException {
        var x509EncodedKeySpec = new X509EncodedKeySpec(object.getEncoded());
        var pem = "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getMimeEncoder().encodeToString(x509EncodedKeySpec.getEncoded()) +
                "\n-----END PUBLIC KEY-----";
        outputStream.write(this.textEncryptor.encrypt(pem).getBytes());
    }
}


@Component
class Keys {

    RSAKeyPairs generatesKeyPairs(String keyId, Instant created) {
        var keyPair = generateRsaKey();
        var publicKey = (RSAPublicKey) keyPair.getPublic();
        var privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKeyPairs(keyId, created, privateKey, publicKey);
    }

    private KeyPair generateRsaKey() {
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        }//
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }
}


@Repository
class CustomKeyRepository {


    private final RsaPrivateKeyConverter rsaPrivateKeyConverter;
    private final RsaPublicKeyConverter rsaPublicKeyConverter;
    private final KeyRepository keyRepository;

    public CustomKeyRepository(RsaPrivateKeyConverter rsaPrivateKeyConverter, RsaPublicKeyConverter rsaPublicKeyConverter, KeyRepository keyRepository) {
        this.rsaPrivateKeyConverter = rsaPrivateKeyConverter;
        this.rsaPublicKeyConverter = rsaPublicKeyConverter;
        this.keyRepository = keyRepository;
    }

    public void save(RSAKeyPairs keyPair) {
        try (var privateBAOS = new ByteArrayOutputStream(); var publicBAOS = new ByteArrayOutputStream()) {
            rsaPrivateKeyConverter.serialize(keyPair.getPrivateKey(), privateBAOS);
            rsaPublicKeyConverter.serialize(keyPair.getPublicKey(), publicBAOS);
            var updated = keyRepository.savePairs(keyPair.getId(), privateBAOS.toString(), publicBAOS.toString(), keyPair.getCreated());
            Assert.state(updated == 0 || updated == 1, "no more than one record should have been updated");
        } catch (IOException e) {
            throw new IllegalArgumentException("there's been an exception", e);
        }
    }

}


interface KeyRepository extends CrudRepository<RSAKeyPairs, String> {
    String INSERT = """
            insert into rsa_key_pairs (id, private_key, public_key, created) values (?, ?, ?, ?)
            on conflict on constraint rsa_key_pairs_id_created_key do nothing
            """;

    @Modifying
    @Query(value = INSERT, nativeQuery = true)
    int savePairs(String id, String privateKey, String publicKey, Instant created);
}



