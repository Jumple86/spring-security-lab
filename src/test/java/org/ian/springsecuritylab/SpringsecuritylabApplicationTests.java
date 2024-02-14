package org.ian.springsecuritylab;

import org.ian.springsecuritylab.dao.UserDao;
import org.ian.springsecuritylab.model.Role;
import org.ian.springsecuritylab.model.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;

@SpringBootTest
class SpringsecuritylabApplicationTests {

    @Autowired
    UserDao userDao;

    @Test
    void contextLoads() {
        User u1 = new User();
        u1.setAccountNonExpired(true);
        u1.setAccountNonLocked(true);
        u1.setCredentialsNonExpired(true);
        u1.setEnabled(true);
        u1.setUsername("user1");
        u1.setPassword("123");

        List<Role> roles1 = new ArrayList<>();
        Role r1 = new Role();
        r1.setName("ROLE_ADMIN");
        r1.setNameZh("管理員");
        roles1.add(r1);
        u1.setRoles(roles1);
        userDao.save(u1);

        User u2 = new User();
        u2.setAccountNonExpired(true);
        u2.setAccountNonLocked(true);
        u2.setCredentialsNonExpired(true);
        u2.setEnabled(true);
        u2.setUsername("user2");
        u2.setPassword("123");

        List<Role> roles2 = new ArrayList<>();
        Role r2 = new Role();
        r2.setName("ROLE_USER");
        r2.setNameZh("一般用戶");
        roles2.add(r2);
        u2.setRoles(roles2);
        userDao.save(u2);
    }

}
