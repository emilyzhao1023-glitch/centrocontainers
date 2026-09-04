from pathlib import Path
from PIL import Image

ROOT = Path(__file__).resolve().parents[1] / "public" / "images"
SOURCES = [
    ROOT / "container-spare-parts-exploded-view.png",
    ROOT / "about" / "about-sheet-processing.png",
    ROOT / "about" / "about-factory-overview.png",
]

for source in SOURCES:
    destination = source.with_name(f"{source.stem}-optimized.webp")
    with Image.open(source) as image:
        image.save(destination, "WEBP", quality=86, method=6)
    print(f"{source.name}: {source.stat().st_size} -> {destination.stat().st_size} bytes")
