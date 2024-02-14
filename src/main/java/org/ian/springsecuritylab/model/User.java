package org.ian.springsecuritylab.model;

import jakarta.persistence.*;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Setter
@Entity(name = "user")
//@EqualsAndHashCode(of = {"id"})
public class User implements UserDetails {
    @Getter
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;
    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.PERSIST)
    @Getter
    private List<Role> roles;
    private boolean accountNonExpired;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;
    private boolean enabled;

    // 返回用戶的角色
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (Role role : getRoles()) {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        }

        return authorities;
    }

    // 返回用戶密碼
    @Override
    public String getPassword() {
        return password;
    }

    // 返回用戶名稱
    @Override
    public String getUsername() {
        return username;
    }

    // 帳號是否未過期
    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    // 帳號是否未鎖定
    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    // 憑證是否未過期
    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    // 帳戶是否可用
    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public boolean equals(Object obj) {
        if (obj instanceof User user) {
            return this.username.equals(user.getUsername());
        } else {
            return false;
        }
    }

    public int hashCode() {
        return this.username.hashCode();
    }
}
