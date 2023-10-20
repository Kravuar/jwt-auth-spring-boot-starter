package net.kravuar.jwtauth;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Payload;
import lombok.RequiredArgsConstructor;
import net.kravuar.jwtauth.components.JWTAuthenticationProvider;
import net.kravuar.jwtauth.components.JWTUtils;
import net.kravuar.jwtauth.components.props.JWTProps;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;

import java.util.function.Function;

@Configuration
@RequiredArgsConstructor
public class AuthenticationManagerConfiguration {
    private final JWTProps jwtProps;

    @Bean
    @ConditionalOnMissingBean
    public Function<DecodedJWT, Object> principalExtractor() {
        return Payload::getSubject;
    }

    @Autowired
    public void authenticationManagerConfigure(AuthenticationManagerBuilder authenticationManagerBuilder, JWTUtils jwtUtils, Function<DecodedJWT, Object> principalExtractor) {
        var jwtProvider = new JWTAuthenticationProvider(
                principalExtractor,
                jwtUtils,
                jwtProps
        );
        authenticationManagerBuilder.authenticationProvider(jwtProvider);
    }

    @Bean
    protected AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
