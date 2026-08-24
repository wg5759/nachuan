# 生成 app 图标：聚合器「中心枢纽 + 多节点」概念，扁平现代风。2x 超采样抗锯齿 → 1024 PNG。
import math
from PIL import Image, ImageDraw

S = 1024
SS = 2
N = S * SS

# 渐变背景（竖直：靛蓝 → 蓝）：用 1×N 列再拉伸，避免逐像素慢
col = Image.new("RGBA", (1, N))
top, bot = (46, 49, 124), (37, 99, 235)
for y in range(N):
    t = y / (N - 1)
    col.putpixel(
        (0, y),
        (
            int(top[0] + (bot[0] - top[0]) * t),
            int(top[1] + (bot[1] - top[1]) * t),
            int(top[2] + (bot[2] - top[2]) * t),
            255,
        ),
    )
grad = col.resize((N, N))

# 圆角方形遮罩
mask = Image.new("L", (N, N), 0)
ImageDraw.Draw(mask).rounded_rectangle(
    [88 * SS, 88 * SS, N - 88 * SS, N - 88 * SS], radius=210 * SS, fill=255
)
img = Image.new("RGBA", (N, N), (0, 0, 0, 0))
img.paste(grad, (0, 0), mask)

d = ImageDraw.Draw(img)
cx = cy = N // 2
R = 250 * SS
node_r = 50 * SS
hub_r = 98 * SS
light = (224, 231, 255, 255)
line = (147, 197, 253, 230)

pts = []
for i in range(6):
    a = math.radians(-90 + i * 60)
    pts.append((cx + int(R * math.cos(a)), cy + int(R * math.sin(a))))
for x, y in pts:  # 连线在节点之下
    d.line([(cx, cy), (x, y)], fill=line, width=18 * SS)
for x, y in pts:  # 外围节点
    d.ellipse([x - node_r, y - node_r, x + node_r, y + node_r], fill=light)
d.ellipse([cx - hub_r, cy - hub_r, cx + hub_r, cy + hub_r], fill=(255, 255, 255, 255))  # 枢纽
d.ellipse([cx - 46 * SS, cy - 46 * SS, cx + 46 * SS, cy + 46 * SS], fill=(37, 99, 235, 255))  # 枢纽内点

img.resize((S, S), Image.LANCZOS).save("desktop/build/icon.png")
print("saved desktop/build/icon.png")
