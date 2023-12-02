package net.kravuar.jwtauth;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Payload;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import net.kravuar.jwtauth.components.JWTAuthenticationProvider;
import net.kravuar.jwtauth.components.JWTUtils;
import net.kravuar.jwtauth.components.PrincipalExtractor;
import net.kravuar.jwtauth.components.props.JWTProps;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Configuration
@RequiredArgsConstructor
public class JWTConfiguration {
    private final JWTProps jwtProps;

    @Bean
    @ConditionalOnMissingBean
    @SneakyThrows
    public Algorithm algorithm() {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var keyPair = generator.generateKeyPair();
        var publicKey = (RSAPublicKey) keyPair.getPublic();
        var privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return Algorithm.RSA256(publicKey, privateKey);
    }

    @Bean
    @ConditionalOnMissingBean
    public PrincipalExtractor principalExtractor() {
        return Payload::getSubject;
    }

    @Bean
    public JWTUtils jwtUtils(Algorithm algorithm) {
        return new JWTUtils(algorithm, jwtProps);
    }

    @Bean
    public JWTAuthenticationProvider jwtAuthenticationProvider(JWTUtils jwtUtils, PrincipalExtractor principalExtractor) {
        return new JWTAuthenticationProvider(
                principalExtractor,
                jwtUtils,
                jwtProps
        );
    }
}
