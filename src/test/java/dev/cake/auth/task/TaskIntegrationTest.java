package dev.cake.auth.task;

import dev.cake.auth.common.exception.EmailNotVerifiedException;
import dev.cake.auth.common.exception.ResourceNotFoundException;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static dev.cake.auth.task.TaskFixtures.DESCRIPTION;
import static dev.cake.auth.task.TaskFixtures.DEADLINE;
import static dev.cake.auth.task.TaskFixtures.NAME;
import static dev.cake.auth.task.TaskFixtures.aCreateTaskRequest;
import static dev.cake.auth.task.TaskFixtures.anUpdateTaskRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;

@Transactional
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class TaskIntegrationTest extends TaskTestSupport {

    @Autowired
    TaskService taskService;
    @Autowired
    EntityManager entityManager;

    @Test
    void create_persists_task_and_returns_response() {
        var user = persistUser(true);
        var createTaskRequest = aCreateTaskRequest().build();

        var taskResponse = taskService.create(user.getPublicId(), createTaskRequest);
        var optTask = taskRepository.findByPublicIdAndUser(taskResponse.id(), user);

        assertThat(optTask).isPresent();
        assertThat(optTask.get().getName()).isEqualTo(createTaskRequest.name());
        assertThat(optTask.get().getDescription()).isEqualTo(createTaskRequest.description());
        assertThat(optTask.get().getDeadline()).isAfter(Instant.now());
        assertThat(optTask.get().getStatus()).isEqualTo(TaskStatus.TODO);
    }

    @Test
    void all_operations_throw_when_user_not_found() {
        var createTaskRequest = aCreateTaskRequest().build();
        var updateTaskRequest = anUpdateTaskRequest().build();
        UUID randomUuid = UUID.randomUUID();
        assertThatThrownBy(() -> taskService.create(randomUuid, createTaskRequest))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("%s '%s' not found", "User", randomUuid.toString());
        assertThatThrownBy(() -> taskService.get(randomUuid, UUID.randomUUID()))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("%s '%s' not found", "User", randomUuid.toString());
        assertThatThrownBy(() -> taskService.list(randomUuid, TaskStatus.TODO))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("%s '%s' not found", "User", randomUuid.toString());
        assertThatThrownBy(() -> taskService.update(randomUuid, UUID.randomUUID(), updateTaskRequest))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("%s '%s' not found", "User", randomUuid.toString());
        assertThatThrownBy(() -> taskService.delete(randomUuid, UUID.randomUUID()))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("%s '%s' not found", "User", randomUuid.toString());
    }

    @Test
    void all_operations_throw_when_user_email_not_verified() {
        var user = persistUser(false);
        var createTaskRequest = aCreateTaskRequest().build();
        var updateTaskRequest = anUpdateTaskRequest().build();

        assertThatThrownBy(() -> taskService.create(user.getPublicId(), createTaskRequest))
                .isInstanceOf(EmailNotVerifiedException.class);
        assertThatThrownBy(() -> taskService.get(user.getPublicId(), UUID.randomUUID()))
                .isInstanceOf(EmailNotVerifiedException.class);
        assertThatThrownBy(() -> taskService.list(user.getPublicId(), TaskStatus.TODO))
                .isInstanceOf(EmailNotVerifiedException.class);
        assertThatThrownBy(() -> taskService.update(user.getPublicId(), UUID.randomUUID(), updateTaskRequest))
                .isInstanceOf(EmailNotVerifiedException.class);
        assertThatThrownBy(() -> taskService.delete(user.getPublicId(), UUID.randomUUID()))
                .isInstanceOf(EmailNotVerifiedException.class);
    }

    @Test
    void update_changes_task_fields() {
        var user = persistUser(true);
        var taskCreateResponse = taskService.create(user.getPublicId(), aCreateTaskRequest().build());

        var optTask = taskRepository.findByPublicIdAndUser(taskCreateResponse.id(), user);
        assertThat(optTask).isPresent();

        var task = optTask.get();
        var updateTaskRequest = anUpdateTaskRequest().build();
        taskService.update(user.getPublicId(), task.getPublicId(), updateTaskRequest);

        entityManager.flush();
        entityManager.clear();

        var updated = taskRepository.findByPublicIdAndUser(task.getPublicId(), user).orElseThrow();
        assertThat(updated.getName()).isEqualTo(updateTaskRequest.name());
        assertThat(updated.getDescription()).isEqualTo(updateTaskRequest.description());
        assertThat(updated.getStatus()).isEqualTo(updateTaskRequest.status());
        assertThat(updated.getDeadline()).isCloseTo(updateTaskRequest.deadline(), within(1, ChronoUnit.MILLIS));
    }

    @Test
    void update_get_delete_throw_when_task_not_found() {
        var user = persistUser(true);
        var updateTaskRequest = anUpdateTaskRequest().build();

        var randomUuid = UUID.randomUUID();
        assertThatThrownBy(() -> taskService.update(user.getPublicId(), randomUuid, updateTaskRequest))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("%s '%s' not found", "Task", randomUuid.toString());
        assertThatThrownBy(() -> taskService.get(user.getPublicId(), randomUuid))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("%s '%s' not found", "Task", randomUuid.toString());
        assertThatThrownBy(() -> taskService.delete(user.getPublicId(), randomUuid))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("%s '%s' not found", "Task", randomUuid.toString());
    }

    @Test
    void delete_removes_task() {
        var user = persistUser(true);
        var taskCreateResponse = taskService.create(user.getPublicId(), aCreateTaskRequest().build());

        var optTask = taskRepository.findByPublicIdAndUser(taskCreateResponse.id(), user);
        assertThat(optTask).isPresent();

        var task = optTask.get();
        taskService.delete(user.getPublicId(), task.getPublicId());
        assertThat(taskRepository.findById(task.getId())).isEmpty();
    }

    @Test
    void get_returns_task() {
        var user = persistUser(true);
        var taskCreateResponse = taskService.create(user.getPublicId(), aCreateTaskRequest().build());

        var optTask = taskRepository.findByPublicIdAndUser(taskCreateResponse.id(), user);
        assertThat(optTask).isPresent();

        var task = optTask.get();
        var taskResponse = taskService.get(user.getPublicId(), task.getPublicId());
        assertThat(taskResponse.name()).isEqualTo(NAME);
        assertThat(taskResponse.description()).isEqualTo(DESCRIPTION);
        assertThat(taskResponse.deadline()).isCloseTo(DEADLINE, within(1, ChronoUnit.MILLIS));
    }

    @Test
    void list_returns_all_tasks_when_status_is_null() {
        var user = persistUser(true);
        persistTask(user, TaskStatus.TODO);
        persistTask(user, TaskStatus.IN_PROGRESS);
        persistTask(user, TaskStatus.COMPLETED);

        var tasks = taskService.list(user.getPublicId(), null);

        assertThat(tasks)
                .hasSize(3)
                .extracting(TaskResponse::status)
                .containsExactlyInAnyOrder(TaskStatus.TODO, TaskStatus.IN_PROGRESS, TaskStatus.COMPLETED);
    }

    @Test
    void list_returns_only_tasks_matching_status() {
        var user = persistUser(true);
        var firstTodo = persistTask(user, TaskStatus.TODO);
        var secondTodo = persistTask(user, TaskStatus.TODO);
        persistTask(user, TaskStatus.COMPLETED);

        var tasks = taskService.list(user.getPublicId(), TaskStatus.TODO);

        assertThat(tasks)
                .extracting(TaskResponse::id)
                .containsExactlyInAnyOrder(firstTodo.getPublicId(), secondTodo.getPublicId());
    }

    @Test
    void list_returns_empty_when_user_has_no_tasks() {
        var user = persistUser(true);

        assertThat(taskService.list(user.getPublicId(), null)).isEmpty();
    }

    @Test
    void get_update_delete_isolate_task_by_owner() {
        var owner = persistUser("owner", "owner@dev.com", true);
        var intruder = persistUser("intruder", "intruder@dev.com", true);
        var taskId = persistTask(owner, TaskStatus.TODO).getPublicId();

        assertThatThrownBy(() -> taskService.get(intruder.getPublicId(), taskId))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("%s '%s' not found", "Task", taskId.toString());
        assertThatThrownBy(() -> taskService.update(intruder.getPublicId(), taskId, anUpdateTaskRequest().build()))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("%s '%s' not found", "Task", taskId.toString());
        assertThatThrownBy(() -> taskService.delete(intruder.getPublicId(), taskId))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("%s '%s' not found", "Task", taskId.toString());

        assertThat(taskService.list(intruder.getPublicId(), null)).isEmpty();

        assertThat(taskService.get(owner.getPublicId(), taskId).id()).isEqualTo(taskId);
    }

}
