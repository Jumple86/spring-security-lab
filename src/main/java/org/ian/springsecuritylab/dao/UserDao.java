package org.ian.springsecuritylab.dao;

import org.ian.springsecuritylab.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserDao extends JpaRepository<User, Long> {
    User findUserByUsername(String username);
}
