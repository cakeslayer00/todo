package dev.cake.auth.task;

import dev.cake.auth.identity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

import static dev.cake.auth.task.TaskFixtures.DEADLINE;
import static dev.cake.auth.task.TaskFixtures.DESCRIPTION;
import static dev.cake.auth.task.TaskFixtures.NAME;
import static dev.cake.auth.task.TaskFixtures.UPDATED_DEADLINE;
import static dev.cake.auth.task.TaskFixtures.UPDATED_DESCRIPTION;
import static dev.cake.auth.task.TaskFixtures.UPDATED_NAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;

@AutoConfigureMockMvc
@Transactional
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class TaskControllerTest extends TaskTestSupport {

    @Autowired
    MockMvcTester mockMvc;

    private User user;

    @BeforeEach
    void seedUser() {
        user = persistUser(true);
    }

    @Test
    void create_returns_201_with_location_and_persists_task_for_caller() {
        assertThat(mockMvc.post().uri("/api/v1/tasks")
                .with(asUser(user))
                .contentType(MediaType.APPLICATION_JSON)
                .content(createTaskBody())
                .exchange())
                .hasStatus(HttpStatus.CREATED)
                .headers().containsHeader("Location");

        assertThat(taskRepository.findAllByUser(user))
                .singleElement()
                .satisfies(task -> assertThat(task.getName()).isEqualTo(NAME));
    }

    @Test
    void create_without_authentication_returns_401() {
        assertThat(mockMvc.post().uri("/api/v1/tasks")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createTaskBody())
                .exchange())
                .hasStatus(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void create_with_blank_name_and_past_deadline_returns_400_with_field_errors() {
        assertThat(mockMvc.post().uri("/api/v1/tasks")
                .with(asUser(user))
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"name": "", "description": "whatever", "deadline": "2000-01-01T00:00:00Z"}
                        """)
                .exchange())
                .hasStatus(HttpStatus.BAD_REQUEST)
                .bodyJson()
                .convertTo(ProblemDetail.class)
                .satisfies(detail -> {
                    assertThat(detail.getDetail()).contains("name");
                    assertThat(detail.getDetail()).contains("deadline");
                });
    }

    @Test
    void create_for_unverified_user_returns_403() {
        var unverified = persistUser("pending", "pending@dev.com", false);

        assertThat(mockMvc.post().uri("/api/v1/tasks")
                .with(asUser(unverified))
                .contentType(MediaType.APPLICATION_JSON)
                .content(createTaskBody())
                .exchange())
                .hasStatus(HttpStatus.FORBIDDEN);
    }

    @Test
    void get_returns_200_with_task() {
        var task = persistTask(user);

        assertThat(mockMvc.get().uri("/api/v1/tasks/{id}", task.getPublicId())
                .with(asUser(user))
                .exchange())
                .hasStatusOk()
                .bodyJson()
                .convertTo(TaskResponse.class)
                .satisfies(response -> {
                    assertThat(response.id()).isEqualTo(task.getPublicId());
                    assertThat(response.name()).isEqualTo(NAME);
                });
    }

    @Test
    void get_unknown_task_returns_404() {
        assertThat(mockMvc.get().uri("/api/v1/tasks/{id}", UUID.randomUUID())
                .with(asUser(user))
                .exchange())
                .hasStatus(HttpStatus.NOT_FOUND);
    }

    @Test
    void list_returns_200_with_callers_tasks() {
        persistTask(user);
        persistTask(user);

        assertThat(mockMvc.get().uri("/api/v1/tasks")
                .with(asUser(user))
                .exchange())
                .hasStatusOk()
                .bodyJson()
                .extractingPath("$.length()").isEqualTo(2);
    }

    @Test
    void update_returns_200_with_updated_task() {
        var task = persistTask(user);

        assertThat(mockMvc.put().uri("/api/v1/tasks/{id}", task.getPublicId())
                .with(asUser(user))
                .contentType(MediaType.APPLICATION_JSON)
                .content(updateTaskBody())
                .exchange())
                .hasStatusOk()
                .bodyJson()
                .convertTo(TaskResponse.class)
                .satisfies(response -> assertThat(response.status()).isEqualTo(TaskStatus.CANCELED));
    }

    @Test
    void delete_returns_204_and_removes_task() {
        var task = persistTask(user);

        assertThat(mockMvc.delete().uri("/api/v1/tasks/{id}", task.getPublicId())
                .with(asUser(user))
                .exchange())
                .hasStatus(HttpStatus.NO_CONTENT);

        assertThat(taskRepository.findById(task.getId())).isEmpty();
    }

    private static RequestPostProcessor asUser(User user) {
        return jwt().jwt(token -> token.subject(user.getPublicId().toString()));
    }

    private static String createTaskBody() {
        return """
                {"name": "%s", "description": "%s", "deadline": "%s"}
                """.formatted(NAME, DESCRIPTION, DEADLINE);
    }

    private static String updateTaskBody() {
        return """
                {"name": "%s", "description": "%s", "status": "CANCELED", "deadline": "%s"}
                """.formatted(UPDATED_NAME, UPDATED_DESCRIPTION, UPDATED_DEADLINE);
    }
}
