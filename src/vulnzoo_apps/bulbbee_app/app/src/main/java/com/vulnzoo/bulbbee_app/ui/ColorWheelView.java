package com.vulnzoo.bulbbee_app.ui;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RadialGradient;
import android.graphics.Shader;
import android.graphics.SweepGradient;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;

/**
 * Hue / saturation wheel. One gesture replaces the three R/G/B Sliders; the
 * value still leaves as {"color":[r,g,b]} on the Control characteristic.
 */
public class ColorWheelView extends View {

    public interface OnColorPickedListener {
        /** Called continuously while dragging. Throttle writes in the caller. */
        void onColorPicked(int color, float hue, float sat);
    }

    private static final int[] HUES = {
            0xFF00FFFF, 0xFF0000FF, 0xFFFF00FF, 0xFFFF0000,
            0xFFFFFF00, 0xFF00FF00, 0xFF00FFFF
    };

    private final Paint wheel = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint white = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint knob = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint knobRing = new Paint(Paint.ANTI_ALIAS_FLAG);

    private float hue = 36f, sat = 0.72f;
    private OnColorPickedListener listener;

    public ColorWheelView(Context c) { this(c, null); }

    public ColorWheelView(Context c, AttributeSet a) {
        super(c, a);
        knobRing.setStyle(Paint.Style.STROKE);
        knobRing.setStrokeWidth(dp(3));
        knobRing.setColor(Color.WHITE);
    }

    public void setOnColorPickedListener(OnColorPickedListener l) { this.listener = l; }

    public void setHueSat(float hue, float sat) {
        this.hue = hue; this.sat = Math.max(0f, Math.min(1f, sat));
        invalidate();
    }

    public int getColor() { return Color.HSVToColor(new float[]{hue, sat, 1f}); }

    @Override protected void onSizeChanged(int w, int h, int ow, int oh) {
        super.onSizeChanged(w, h, ow, oh);
        float cx = w / 2f, cy = h / 2f, r = Math.min(cx, cy);
        SweepGradient sg = new SweepGradient(cx, cy, HUES, null);
        android.graphics.Matrix m = new android.graphics.Matrix();
        m.setRotate(90f, cx, cy);           // 0 degrees at the top, like the prototype
        sg.setLocalMatrix(m);
        wheel.setShader(sg);
        white.setShader(new RadialGradient(cx, cy, r,
                new int[]{0xFFFFFFFF, 0x00FFFFFF}, new float[]{0f, 0.72f}, Shader.TileMode.CLAMP));
    }

    @Override protected void onDraw(Canvas canvas) {
        float cx = getWidth() / 2f, cy = getHeight() / 2f, r = Math.min(cx, cy);
        canvas.drawCircle(cx, cy, r, wheel);
        canvas.drawCircle(cx, cy, r, white);

        double rad = Math.toRadians(hue);
        float kx = cx + (float) Math.sin(rad) * sat * r;
        float ky = cy - (float) Math.cos(rad) * sat * r;
        knob.setColor(getColor());
        canvas.drawCircle(kx, ky, dp(11), knob);
        canvas.drawCircle(kx, ky, dp(11), knobRing);
    }

    @Override public boolean onTouchEvent(MotionEvent e) {
        int action = e.getActionMasked();
        if (action != MotionEvent.ACTION_DOWN && action != MotionEvent.ACTION_MOVE) {
            return super.onTouchEvent(e);
        }
        if (action == MotionEvent.ACTION_DOWN) {
            getParent().requestDisallowInterceptTouchEvent(true);
        }
        float cx = getWidth() / 2f, cy = getHeight() / 2f, r = Math.min(cx, cy);
        float dx = e.getX() - cx, dy = e.getY() - cy;
        sat = Math.min(1f, (float) Math.hypot(dx, dy) / r);
        float ang = (float) Math.toDegrees(Math.atan2(dy, dx)) + 90f;
        hue = (ang + 360f) % 360f;
        invalidate();
        if (listener != null) listener.onColorPicked(getColor(), hue, sat);
        return true;
    }

    private float dp(float v) { return v * getResources().getDisplayMetrics().density; }
}
