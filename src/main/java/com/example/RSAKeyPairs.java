package com.example;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;

@Entity
@Table(name = "rsa_key_pairs")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RSAKeyPairs {

    @Id
    private String id;
    private Instant created;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

}
