package net.kravuar.jwtauth;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

@Getter
public class JWTAuthenticationToken extends AbstractAuthenticationToken {
    private final String jwt;
    private final String subject;

    public JWTAuthenticationToken(String jwt) {
        super(Collections.emptyList());
        this.jwt = jwt;
        this.subject = null;
        this.setAuthenticated(false);
    }

    public JWTAuthenticationToken(String jwt, String subject, Collection<? extends GrantedAuthority> authorities) {
        super(Collections.emptyList());
        this.jwt = jwt;
        this.subject = subject;
        super.getAuthorities().addAll(authorities);
        this.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return isAuthenticated()
                ? this.subject
                : this.jwt;
    }
}
