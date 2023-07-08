package net.kravuar.jwtauth;

import com.auth0.jwt.algorithms.Algorithm;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

@AutoConfiguration(after = {SecurityAutoConfiguration.class})
@RequiredArgsConstructor
@EnableMethodSecurity
@EnableWebSecurity
@EnableConfigurationProperties(JWTAuthProps.class)
@ConditionalOnProperty(value = "jwt-auth.enabled", havingValue = "true", matchIfMissing = true)
@ConditionalOnClass({HttpSecurity.class, HttpServletRequest.class})
public class JWTAuthSpringBootAutoConfiguration {
    private final JWTAuthProps JWTAuthProps;

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
    public JWTUtils jwtUtils(Algorithm algorithm) {
        return new JWTUtils(algorithm, JWTAuthProps.jwt);
    }

    @Bean
    @ConditionalOnMissingBean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(JWTAuthProps.corsAllowed);
        configuration.setAllowCredentials(true);
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public HttpSecurity httpSecurity(HttpSecurity httpSecurity, AuthenticationManagerBuilder authenticationManagerBuilder, JWTUtils jwtUtils) throws Exception {
        var unauthenticated = new OrRequestMatcher(
                JWTAuthProps.unauthenticatedServlets.stream()
                        .map(AntPathRequestMatcher::new)
                        .map(RequestMatcher.class::cast)
                        .toList()
        );

        var jwtProvider = new JWTAuthenticationProvider(
                jwtUtils,
                JWTAuthProps.jwt
        );
        authenticationManagerBuilder.authenticationProvider(jwtProvider);
        var authenticationManager = authenticationManagerBuilder.build();

        var jwtFilter = new JWTAuthFilter(unauthenticated, JWTAuthProps.jwt.accessCookieName, authenticationManager);

        return httpSecurity
                .sessionManagement(configurer -> configurer
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .httpBasic(Customizer.withDefaults())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(unauthenticated).permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterAfter(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
