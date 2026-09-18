package com.vulnzoo.bulbbee_app.ui;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Shader;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;

/**
 * Warm-to-cool white ramp, 2000..6500 K. Most evenings people want warm white,
 * not a hue - this is the shortest path to it. Converted to RGB before it hits
 * the Control characteristic, so the device protocol is unchanged.
 */
public class TempRampView extends View {

    public interface OnKelvinChangeListener { void onKelvinChange(int kelvin, int color); }

    public static final int MIN_K = 2000, MAX_K = 6500;

    private final Paint ramp = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint marker = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF rect = new RectF();

    private int kelvin = 2700;
    private OnKelvinChangeListener listener;

    public TempRampView(Context c) { this(c, null); }

    public TempRampView(Context c, AttributeSet a) {
        super(c, a);
        marker.setColor(0xFFF6EDE2);
    }

    public void setOnKelvinChangeListener(OnKelvinChangeListener l) { this.listener = l; }

    public void setKelvin(int k) {
        kelvin = Math.max(MIN_K, Math.min(MAX_K, k));
        invalidate();
    }

    public int getKelvin() { return kelvin; }

    @Override protected void onSizeChanged(int w, int h, int ow, int oh) {
        super.onSizeChanged(w, h, ow, oh);
        ramp.setShader(new LinearGradient(0, 0, w, 0,
                new int[]{0xFFFF9329, 0xFFFFC57A, 0xFFFFF3E2, 0xFFF2F6FF, 0xFFCFE2FF},
                new float[]{0f, 0.25f, 0.5f, 0.75f, 1f}, Shader.TileMode.CLAMP));
    }

    @Override protected void onDraw(Canvas canvas) {
        float r = dp(20);
        rect.set(0, 0, getWidth(), getHeight());
        canvas.drawRoundRect(rect, r, r, ramp);

        float x = getWidth() * (kelvin - MIN_K) / (float) (MAX_K - MIN_K);
        canvas.drawRoundRect(x - dp(2), -dp(3), x + dp(2), getHeight() + dp(3), dp(2), dp(2), marker);
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
        kelvin = Math.round(MIN_K + p * (MAX_K - MIN_K));
        invalidate();
        if (listener != null) listener.onKelvinChange(kelvin, kelvinToRgb(kelvin));
        return true;
    }

    /** Tanner Helland's approximation, clamped. Good enough for a WS2812 ring. */
    public static int kelvinToRgb(int k) {
        double t = k / 100.0, r, g, b;
        if (t <= 66) {
            r = 255;
            g = 99.4708025861 * Math.log(t) - 161.1195681661;
        } else {
            r = 329.698727446 * Math.pow(t - 60, -0.1332047592);
            g = 288.1221695283 * Math.pow(t - 60, -0.0755148492);
        }
        if (t >= 66) b = 255;
        else if (t <= 19) b = 0;
        else b = 138.5177312231 * Math.log(t - 10) - 305.0447927307;
        return Color.rgb(clamp(r), clamp(g), clamp(b));
    }

    private static int clamp(double v) { return (int) Math.max(0, Math.min(255, Math.round(v))); }

    private float dp(float v) { return v * getResources().getDisplayMetrics().density; }
}
