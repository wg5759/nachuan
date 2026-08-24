"""一次性把 LLMLingua-2 的 safetensors 导出成 ONNX（**仅开发步骤**，需 torch/transformers）。

引擎运行期是 torch-free 的（只用 onnxruntime+tokenizers，见 orchestrator/compress.py）；
但本机已有 ModelScope 下来的 safetensors，跑一次本脚本就能生成 onnx 给运行期用，省得再去下。
空版/商用分发时改为下预导出的 onnx（或在有 torch 的机器上跑一次本脚本）。

用法（本机按锁文件装好 torch/transformers/onnxscript/onnx 后运行；禁止临时 pip 安装）：
    PYTHONIOENCODING=utf-8 .venv/Scripts/python.exe scripts/_export_llmlingua2_onnx.py
产物：models/llmlingua-2-bert-base-multilingual-cased-meetingbank/onnx/model.onnx（fp32, ~710MB）
量化到 ~178MB（compress.py 运行期优先用 model_quantized.onnx）：
    from onnxruntime.quantization import quantize_dynamic, QuantType
    quantize_dynamic(d+'/onnx/model.onnx', d+'/onnx/model_quantized.onnx', weight_type=QuantType.QInt8)
想要 fp32 的更干净压缩质量（换 ~710MB 体积）：保留 model.onnx、删掉 model_quantized.onnx 即可。
"""

from __future__ import annotations

import os

os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

MODEL_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models",
    "llmlingua-2-bert-base-multilingual-cased-meetingbank",
)


def main() -> None:
    import torch
    from transformers import AutoModelForTokenClassification, AutoTokenizer

    print(f"加载模型：{MODEL_DIR}")
    model = AutoModelForTokenClassification.from_pretrained(MODEL_DIR, local_files_only=True)
    model.eval()
    tok = AutoTokenizer.from_pretrained(MODEL_DIR, local_files_only=True)

    class Wrap(torch.nn.Module):
        """只吐 logits（torch.onnx.export 要纯 tensor 输出，不要 dataclass）。"""

        def __init__(self, m: torch.nn.Module) -> None:
            super().__init__()
            self.m = m

        def forward(self, input_ids, attention_mask, token_type_ids):  # noqa: ANN001
            return self.m(
                input_ids=input_ids,
                attention_mask=attention_mask,
                token_type_ids=token_type_ids,
            ).logits

    wrapped = Wrap(model).eval()  # 包装器也要 eval（否则 dropout 开着、导出告警+结果不稳）

    enc = tok("纳川 hello world 压缩测试", return_tensors="pt")
    inputs = (enc["input_ids"], enc["attention_mask"], enc["token_type_ids"])

    out_dir = os.path.join(MODEL_DIR, "onnx")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "model.onnx")
    print(f"导出 ONNX → {out_path}")
    dyn = {0: "batch", 1: "seq"}
    torch.onnx.export(
        wrapped,
        inputs,
        out_path,
        input_names=["input_ids", "attention_mask", "token_type_ids"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": dyn,
            "attention_mask": dyn,
            "token_type_ids": dyn,
            "logits": {0: "batch", 1: "seq"},
        },
        opset_version=14,
        do_constant_folding=True,
        dynamo=False,  # 用稳的 TorchScript 导出器（支持 dynamic_axes、不打印 emoji 撞 GBK 控制台）
    )
    print(f"完成：{out_path}（{os.path.getsize(out_path) / 1e6:.0f} MB）")
    print("如需量化到 ~180MB：先把 onnx 固定进 lockfile 并用 uv sync --locked 安装")
    print("  from onnxruntime.quantization import quantize_dynamic, QuantType")
    print("  quantize_dynamic(out, out_q, weight_type=QuantType.QInt8)")


if __name__ == "__main__":
    main()
