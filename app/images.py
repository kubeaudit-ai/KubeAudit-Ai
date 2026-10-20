def is_unpinned_image(image: str) -> bool:
    """True when an image reference has no tag, uses ':latest', and has no digest."""
    if not image:
        return True
    if "@" in image:
        return False
    last_segment = image.rsplit("/", 1)[-1]
    if ":" not in last_segment:
        return True
    return last_segment.rsplit(":", 1)[-1] == "latest"
