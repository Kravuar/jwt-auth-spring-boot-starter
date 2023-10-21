package net.kravuar.jwtauth;

import net.kravuar.jwtauth.components.JWTAuthFilter;
import net.kravuar.jwtauth.components.JWTExtractor;
import net.kravuar.jwtauth.components.props.HttpProps;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Scope;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
public class HttpSecurityConfiguration {
    private final OrRequestMatcher unauthenticated;

    public HttpSecurityConfiguration(HttpProps httpProps) {
        this.unauthenticated = new OrRequestMatcher(
                httpProps.getUnauthenticatedEndpoints().stream()
                        .map(AntPathRequestMatcher::new)
                        .map(RequestMatcher.class::cast)
                        .toList()
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public JWTAuthFilter jwtFilter(AuthenticationManager authenticationManager, JWTExtractor jwtExtractor) {
        return new JWTAuthFilter(unauthenticated, authenticationManager, jwtExtractor);
    }

    @Bean
    @Scope("prototype")
    @Primary
    public HttpSecurity httpSecurity(HttpSecurity httpSecurity, JWTAuthFilter jwtFilter) {
        return httpSecurity.addFilterAfter(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
