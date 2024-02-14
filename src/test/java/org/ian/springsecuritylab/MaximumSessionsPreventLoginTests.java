package org.ian.springsecuritylab;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class MaximumSessionsPreventLoginTests {

    @Autowired
    private MockMvc mvc;

    @Test
    void loginOnSecondLoginThenPreventLogin() throws Exception {
        MvcResult mvcResult = this.mvc.perform(formLogin())
                .andExpect(authenticated())
                .andReturn();

        MockHttpSession firstLoginSession = (MockHttpSession) mvcResult.getRequest().getSession();

        this.mvc.perform(
                get("/").session(firstLoginSession))
                .andExpect(authenticated());

        // second login is prevented
        this.mvc.perform(formLogin()).andExpect(unauthenticated());

        // first session is still valid
        this.mvc.perform(get("/").session(firstLoginSession))
                .andExpect(authenticated());
    }
}
