package net.kravuar.jwtauth.components.props;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("jwt-auth.jwt")
@Setter
@Getter
public class JWTProps {
    private String jwtStorageType = "cookie";
    private String tokenPrefix = "Bearer_";
    private String issuer = "jwt-auth";
    private String authoritiesClaimName = "authorities";
    private long accessTokenExpiration = 300;
    private long refreshTokenExpiration = 43200;
}