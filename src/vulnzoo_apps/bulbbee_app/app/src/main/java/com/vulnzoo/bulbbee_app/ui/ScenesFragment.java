package com.vulnzoo.bulbbee_app.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.recyclerview.widget.RecyclerView;

import com.vulnzoo.bulbbee_app.R;

/** Lists the four firmware scenes; a tap sends the scene to the bulb. */
public class ScenesFragment extends Fragment {

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_scenes, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View v, @Nullable Bundle savedInstanceState) {
        LightViewModel vm = new ViewModelProvider(requireActivity()).get(LightViewModel.class);
        RecyclerView list = v.findViewById(R.id.sceneList);
        list.setAdapter(new SceneAdapter(vm::writeScene));
    }
}
