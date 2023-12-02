package net.kravuar.jwtauth;

import lombok.RequiredArgsConstructor;
import net.kravuar.jwtauth.components.*;
import net.kravuar.jwtauth.components.props.HttpProps;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Scope;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@RequiredArgsConstructor
public class HttpSecurityConfiguration {
    private final HttpProps httpProps;

    @Bean
    protected AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    @Scope("prototype")
    @Primary
    public HttpSecurity httpSecurityJWTConfigured(
            HttpSecurity httpSecurity,
            JWTAuthenticationProvider jwtAuthenticationProvider,
            AuthenticationManager authenticationManager,
            JWTExtractor jwtExtractor
    ) {
        var unauthenticated = new OrRequestMatcher(
                httpProps.getUnauthenticatedEndpoints().stream()
                        .map(AntPathRequestMatcher::new)
                        .map(RequestMatcher.class::cast)
                        .toList()
        );
        var jwtFilter = new JWTAuthFilter(unauthenticated, authenticationManager, jwtExtractor);

        httpSecurity.authenticationProvider(jwtAuthenticationProvider);
        httpSecurity.addFilterAfter(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return httpSecurity;
    }
}
