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

        cmd = [
            "docker",
            "build",
            "-t",
            image_tag,
            "-f",
            dockerfile_arg,
            build_context,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )

        if result.returncode != 0:
            error_output = result.stderr or result.stdout
            raise RuntimeError(
                f"Docker build failed for {service_name}: {error_output[-2000:]}"
            )

        return image_tag

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
