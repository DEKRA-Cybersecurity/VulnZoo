package com.vulnzoo.bulbbee_app.ui;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.vulnzoo.bulbbee_app.R;

import java.util.function.Consumer;

/** The four scenes the firmware ships (solid / rainbow / breathe / off). Tapping
 *  one sends {"scene":"<key>"} to Control (0xFF31). */
public class SceneAdapter extends RecyclerView.Adapter<SceneAdapter.Holder> {

    static final class Scene {
        final String key; final int titleRes; final int descRes;
        Scene(String key, int titleRes, int descRes) {
            this.key = key; this.titleRes = titleRes; this.descRes = descRes;
        }
    }

    private static final Scene[] SCENES = {
            new Scene("solid",   R.string.scene_solid,   R.string.scene_solid_desc),
            new Scene("rainbow", R.string.scene_rainbow, R.string.scene_rainbow_desc),
            new Scene("breathe", R.string.scene_breathe, R.string.scene_breathe_desc),
            new Scene("off",     R.string.scene_off,     R.string.scene_off_desc),
    };

    private final Consumer<String> onPick;

    public SceneAdapter(Consumer<String> onPick) { this.onPick = onPick; }

    static final class Holder extends RecyclerView.ViewHolder {
        final TextView title, desc;
        Holder(@NonNull View v) {
            super(v);
            title = v.findViewById(R.id.sceneTitle);
            desc = v.findViewById(R.id.sceneDesc);
        }
    }

    @NonNull
    @Override
    public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        return new Holder(LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_scene, parent, false));
    }

    @Override
    public void onBindViewHolder(@NonNull Holder h, int position) {
        Scene s = SCENES[position];
        h.title.setText(s.titleRes);
        h.desc.setText(s.descRes);
        h.itemView.setOnClickListener(v -> onPick.accept(s.key));
    }

    @Override
    public int getItemCount() { return SCENES.length; }
}
