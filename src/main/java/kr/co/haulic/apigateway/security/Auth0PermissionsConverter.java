package kr.co.haulic.apigateway.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Auth0 JWT의 'permissions' 및 'scope' claim을 GrantedAuthority로 변환.
 *
 * <ul>
 *   <li>permissions: ["cms:read","cms:write"] → PERM_cms:read, PERM_cms:write</li>
 *   <li>scope: "openid profile email" → SCOPE_openid, SCOPE_profile, SCOPE_email</li>
 * </ul>
 */
public class Auth0PermissionsConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private static final String PERMISSIONS_CLAIM = "permissions";
    private static final String SCOPE_CLAIM = "scope";
    private static final String PERM_PREFIX = "PERM_";
    private static final String SCOPE_PREFIX = "SCOPE_";

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        List<GrantedAuthority> authorities = new ArrayList<>();

        // permissions claim → PERM_xxx
        List<String> permissions = jwt.getClaimAsStringList(PERMISSIONS_CLAIM);
        if (permissions != null) {
            for (String perm : permissions) {
                if (perm != null && !perm.isBlank()) {
                    authorities.add(new SimpleGrantedAuthority(PERM_PREFIX + perm));
                }
            }
        }

        // scope claim → SCOPE_xxx
        String scope = jwt.getClaimAsString(SCOPE_CLAIM);
        if (scope != null && !scope.isBlank()) {
            for (String s : scope.split("\\s+")) {
                if (!s.isBlank()) {
                    authorities.add(new SimpleGrantedAuthority(SCOPE_PREFIX + s));
                }
            }
        }

        return authorities;
    }
}
