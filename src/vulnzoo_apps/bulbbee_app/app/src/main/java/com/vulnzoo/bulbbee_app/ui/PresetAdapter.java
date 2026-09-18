package com.vulnzoo.bulbbee_app.ui;

import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.vulnzoo.bulbbee_app.R;

import java.util.function.IntConsumer;

/** Fixed grid of colour swatches for the Light screen's "Presets" mode. */
public class PresetAdapter extends RecyclerView.Adapter<PresetAdapter.Holder> {

    private static final int[] PRESETS = {
            0xFFFFFFFF, 0xFFFFB03F, 0xFFFF6B3D, 0xFFFF3B6E,
            0xFFB56BFF, 0xFF4F8DFF, 0xFF3FE0C0, 0xFF9CFF57
    };

    private final IntConsumer onPick;

    public PresetAdapter(IntConsumer onPick) { this.onPick = onPick; }

    static final class Holder extends RecyclerView.ViewHolder {
        final View swatch;
        Holder(@NonNull View v) { super(v); swatch = v.findViewById(R.id.swatch); }
    }

    @NonNull
    @Override
    public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_preset, parent, false);
        return new Holder(v);
    }

    @Override
    public void onBindViewHolder(@NonNull Holder h, int position) {
        int color = PRESETS[position];
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(color);
        bg.setCornerRadius(h.swatch.getResources().getDisplayMetrics().density * 14);
        bg.setStroke(1, 0x24F6EDE2);
        h.swatch.setBackground(bg);
        h.itemView.setOnClickListener(v -> onPick.accept(color));
    }

    @Override
    public int getItemCount() { return PRESETS.length; }
}
