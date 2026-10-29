"""
AUTO-RECON AI — PyTorch Crash Severity & Trajectory Risk Neural Network
"""

import torch
import torch.nn as nn
from typing import Dict, Any

class CrashSeverityNet(nn.Module):
    """Deep Multi-Layer Perceptron for automotive crash severity and risk estimation."""

    def __init__(self, input_dim: int, num_classes: int = 4):
        super().__init__()
        self.input_dim = input_dim
        self.num_classes = num_classes

        self.feature_extractor = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.25),

            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Dropout(0.15),

            nn.Linear(32, 16),
            nn.ReLU()
        )

        self.classifier_head = nn.Linear(16, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        features = self.feature_extractor(x)
        logits = self.classifier_head(features)
        return logits

    def predict_probabilities(self, x: torch.Tensor) -> torch.Tensor:
        self.eval()
        with torch.no_grad():
            logits = self.forward(x)
            probs = torch.softmax(logits, dim=-1)
        return probs
