import os
import re
import subprocess
import uuid


class DockerService:
    def discover_dockerfiles(self, repo_path: str) -> list[dict]:
        dockerfiles = []
        skip_dirs = {
            ".git",
            "node_modules",
            "vendor",
            "__pycache__",
            ".venv",
            "venv",
        }

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]

            for filename in files:
                if filename == "Dockerfile" or filename.lower().startswith("dockerfile"):
                    full_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(full_path, repo_path).replace("\\", "/")
                    service_name = self._derive_service_name(rel_path)
                    dockerfiles.append(
                        {
                            "dockerfile_path": rel_path,
                            "service_name": service_name,
                            "build_context": root,
                            "dockerfile_full_path": full_path,
                        }
                    )

        dockerfiles.sort(key=lambda x: x["dockerfile_path"])
        return dockerfiles

    def _derive_service_name(self, dockerfile_path: str) -> str:
        directory = os.path.dirname(dockerfile_path)
        if not directory or directory == ".":
            return "root"
        parts = directory.replace("\\", "/").split("/")
        return re.sub(r"[^a-zA-Z0-9_-]", "-", parts[-1]).lower()

    def _buildx_available(self) -> bool:
        result = subprocess.run(
            ["docker", "buildx", "version"],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0

    def _ensure_buildx(self) -> bool:
        if not self._buildx_available():
            return False

        inspect = subprocess.run(
            ["docker", "buildx", "inspect", "vulnsight-builder"],
            capture_output=True,
            text=True,
        )
        if inspect.returncode == 0:
            subprocess.run(
                ["docker", "buildx", "use", "vulnsight-builder"],
                capture_output=True,
                text=True,
            )
            return True

        create = subprocess.run(
            ["docker", "buildx", "create", "--name", "vulnsight-builder", "--use"],
            capture_output=True,
            text=True,
        )
        return create.returncode == 0

    def _clean_build_error(self, stderr: str, stdout: str) -> str:
        combined = f"{stderr or ''}\n{stdout or ''}"
        noise = (
            "DEPRECATED: The legacy builder is deprecated",
            "Install the buildx component",
            "BuildKit is enabled but the buildx component is missing or broken",
            "https://docs.docker.com/go/buildx/",
        )
        lines = [
            line for line in combined.splitlines()
            if line.strip() and not any(fragment in line for fragment in noise)
        ]
        if not lines:
            return combined[-2000:]
        return "\n".join(lines)[-2000:]

    def _run_build(
        self,
        cmd: list[str],
        env: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            env=env,
        )

    def build_image(
        self,
        build_context: str,
        dockerfile_path: str,
        service_name: str,
        scan_uuid: str,
    ) -> str:
        image_tag = f"vulnsight-{service_name}-{scan_uuid}"
        dockerfile_arg = os.path.join(build_context, os.path.basename(dockerfile_path))

        if not os.path.isfile(dockerfile_arg):
            dockerfile_arg = dockerfile_path

        base_env = os.environ.copy()
        build_cmd = [
            "docker",
            "build",
            "-t",
            image_tag,
            "-f",
            dockerfile_arg,
            build_context,
        ]

        attempts: list[tuple[list[str], dict[str, str]]] = []

        if self._ensure_buildx():
            buildx_env = base_env.copy()
            buildx_env["DOCKER_BUILDKIT"] = "1"
            attempts.append(
                (
                    [
                        "docker",
                        "buildx",
                        "build",
                        "--load",
                        "-t",
                        image_tag,
                        "-f",
                        dockerfile_arg,
                        build_context,
                    ],
                    buildx_env,
                )
            )

        buildkit_env = base_env.copy()
        buildkit_env["DOCKER_BUILDKIT"] = "1"
        attempts.append((build_cmd, buildkit_env))

        legacy_env = base_env.copy()
        legacy_env["DOCKER_BUILDKIT"] = "0"
        attempts.append((build_cmd, legacy_env))

        last_result = None
        for cmd, env in attempts:
            result = self._run_build(cmd, env)
            if result.returncode == 0:
                return image_tag
            last_result = result

        error_output = self._clean_build_error(
            last_result.stderr if last_result else "",
            last_result.stdout if last_result else "",
        )
        raise RuntimeError(
            f"Docker build failed for {service_name}: {error_output}"
        )

    def build_all_images(self, repo_path: str, dockerfiles: list[dict]) -> list[dict]:
        scan_uuid = str(uuid.uuid4())[:8]
        built_images = []

        for dockerfile_info in dockerfiles:
            image_name = self.build_image(
                build_context=dockerfile_info["build_context"],
                dockerfile_path=dockerfile_info["dockerfile_full_path"],
                service_name=dockerfile_info["service_name"],
                scan_uuid=scan_uuid,
            )
            built_images.append(
                {
                    **dockerfile_info,
                    "image_name": image_name,
                }
            )

        return built_images

    def remove_image(self, image_name: str):
        subprocess.run(
            ["docker", "rmi", "-f", image_name],
            capture_output=True,
            text=True,
        )
