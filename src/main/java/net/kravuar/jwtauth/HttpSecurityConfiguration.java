package net.kravuar.jwtauth;

import net.kravuar.jwtauth.components.JWTAuthFilter;
import net.kravuar.jwtauth.components.JWTAuthenticationProvider;
import net.kravuar.jwtauth.components.JWTExtractor;
import net.kravuar.jwtauth.components.props.HttpProps;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Scope;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.*;

@Configuration
public class HttpSecurityConfiguration {
    private final RequestMatcher jwtIgnoredPathMatcher;

    public HttpSecurityConfiguration(HttpProps httpProps) {
        var unauthenticated = new OrRequestMatcher(
                httpProps.getUnauthenticatedPathMatchers().stream()
                        .map(AntPathRequestMatcher::new)
                        .map(RequestMatcher.class::cast)
                        .toList()
        );
        var authenticated = new OrRequestMatcher(
                httpProps.getAuthenticatedPathMatchers().stream()
                        .map(AntPathRequestMatcher::new)
                        .map(RequestMatcher.class::cast)
                        .toList()
        );

        this.jwtIgnoredPathMatcher = new AndRequestMatcher(
                unauthenticated,
                new NegatedRequestMatcher(authenticated)
        );
    }


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
        var jwtFilter = new JWTAuthFilter(jwtIgnoredPathMatcher, authenticationManager, jwtExtractor);

        httpSecurity.authenticationProvider(jwtAuthenticationProvider);
        httpSecurity.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return httpSecurity;
    }
}
