package net.kravuar.jwtauth.components;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.function.Function;

@RequiredArgsConstructor
public class JWTAuthenticationProvider implements AuthenticationProvider {
    private final Function<DecodedJWT, Object> principalExtractor;
    private final JWTUtils jwtUtils;
    private final JWTProps jwtProps;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {
            JWTAuthenticationToken bearer = (JWTAuthenticationToken) authentication;
            var decodedJWT = jwtUtils.decode(bearer.getJwt());
            var principal = principalExtractor.apply(decodedJWT);
            var authorities = Arrays.stream(decodedJWT.getClaim(jwtProps.getAuthoritiesClaimName()).asArray(String.class))
                    .map(SimpleGrantedAuthority::new).toList();
            return new JWTAuthenticationToken(decodedJWT, principal, authorities);
        } catch (JWTVerificationException exception) {
            throw new AuthenticationCredentialsNotFoundException(exception.getMessage(), exception);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JWTAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
