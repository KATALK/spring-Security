package security07.model;

import org.springframework.security.core.GrantedAuthority;

/**角色实体类
 * @Author EdiMen
 * @Data 2020/10/10--22:23
 * @Version 1.0
 */
public class SysRole implements GrantedAuthority {

    private Long id;
    private String role;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    @Override
    public String getAuthority() {
        return role;
    }
}
