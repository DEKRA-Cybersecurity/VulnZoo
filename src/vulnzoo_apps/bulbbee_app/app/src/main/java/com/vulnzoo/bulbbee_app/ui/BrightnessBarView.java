package com.vulnzoo.bulbbee_app.ui;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Shader;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;

/**
 * A 56dp-tall brightness target. Same 0..255 range the device uses, but the
 * whole bar is grabbable instead of a 20dp Slider thumb.
 */
public class BrightnessBarView extends View {

    public interface OnBrightnessChangeListener { void onBrightnessChange(int value); }

    private final Paint track = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint fill = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint edge = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint marker = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF rect = new RectF();

    private int value = 178;
    private OnBrightnessChangeListener listener;

    public BrightnessBarView(Context c) { this(c, null); }

    public BrightnessBarView(Context c, AttributeSet a) {
        super(c, a);
        track.setColor(0xFF1A1410);
        edge.setStyle(Paint.Style.STROKE);
        edge.setStrokeWidth(dp(1));
        edge.setColor(0x17F6EDE2);
        marker.setColor(0xD9F6EDE2);
    }

    public void setOnBrightnessChangeListener(OnBrightnessChangeListener l) { this.listener = l; }

    public void setValue(int v) {
        value = Math.max(0, Math.min(255, v));
        invalidate();
    }

    public int getValue() { return value; }

    @Override protected void onSizeChanged(int w, int h, int ow, int oh) {
        super.onSizeChanged(w, h, ow, oh);
        fill.setShader(new LinearGradient(0, 0, w, 0,
                new int[]{0x59FBB03F, 0xFFFBB03F}, new float[]{0f, 1f}, Shader.TileMode.CLAMP));
    }

    @Override protected void onDraw(Canvas canvas) {
        float r = dp(20);
        rect.set(0, 0, getWidth(), getHeight());
        canvas.drawRoundRect(rect, r, r, track);

        float w = getWidth() * (value / 255f);
        if (w > 0) {
            canvas.save();
            canvas.clipRect(0, 0, w, getHeight());
            canvas.drawRoundRect(rect, r, r, fill);
            canvas.restore();
            canvas.drawRect(w - dp(1), 0, w + dp(1), getHeight(), marker);
        }

        rect.inset(dp(0.5f), dp(0.5f));
        canvas.drawRoundRect(rect, r, r, edge);
    }

    @Override public boolean onTouchEvent(MotionEvent e) {
        int action = e.getActionMasked();
        if (action != MotionEvent.ACTION_DOWN && action != MotionEvent.ACTION_MOVE) {
            return super.onTouchEvent(e);
        }
        if (action == MotionEvent.ACTION_DOWN) {
            getParent().requestDisallowInterceptTouchEvent(true);
        }
        float p = Math.max(0f, Math.min(1f, e.getX() / getWidth()));
        value = Math.round(p * 255f);
        invalidate();
        if (listener != null) listener.onBrightnessChange(value);
        return true;
    }

    private float dp(float v) { return v * getResources().getDisplayMetrics().density; }
}
