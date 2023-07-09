package net.kravuar.jwtauth.components;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties("jwt-auth.http")
@Setter
@Getter
public class HttpProps {
    private List<String> unauthenticatedServlets = new ArrayList<>(List.of("/auth/**"));
    private List<String> corsAllowed = new ArrayList<>();
}