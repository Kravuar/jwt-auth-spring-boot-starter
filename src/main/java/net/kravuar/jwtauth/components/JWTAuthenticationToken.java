package net.kravuar.jwtauth.components;

import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

@Getter
public class JWTAuthenticationToken extends AbstractAuthenticationToken {
    private final String jwt;
    private final Object principal;

    public JWTAuthenticationToken(String jwt) {
        super(Collections.emptyList());
        this.jwt = jwt;
        this.principal = null;
    }

    public JWTAuthenticationToken(DecodedJWT jwt, Object principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.jwt = jwt.getToken();
        this.principal = principal;
        this.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }
}
