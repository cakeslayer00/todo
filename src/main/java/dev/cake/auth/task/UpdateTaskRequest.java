package dev.cake.auth.task;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;

@Schema(description = "Details for updating an existing task")
record UpdateTaskRequest(
        @NotBlank @Size(max = 255)
        @Schema(description = "Task name", example = "Write project report")
        String name,

        @Size(max = 255)
        @Schema(description = "Optional task description", example = "Cover Q2 metrics and next steps")
        String description,

        @NotNull
        @Schema(description = "Task status", example = "IN_PROGRESS")
        TaskStatus status,

        @Future
        @Schema(description = "Optional deadline, must be in the future", example = "2026-07-01T12:00:00Z")
        Instant deadline
) {
}
