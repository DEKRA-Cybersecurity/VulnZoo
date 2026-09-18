package com.vulnzoo.bulbbee_app.ui;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RadialGradient;
import android.graphics.Shader;
import android.graphics.SweepGradient;
import android.util.AttributeSet;
import android.view.View;
import android.view.animation.LinearInterpolator;

/**
 * The bulb, drawn. Takes the live colour, dims with brightness, and animates
 * exactly as the WS2812 ring does for the scenes the firmware ships
 * (solid / rainbow / breathe / off). Tap to toggle power.
 *
 * Replaces the old "no feedback at all" control card: this is the only element
 * on the Light screen that moves.
 */
public class BulbOrbView extends View {

    public interface OnPowerToggleListener { void onPowerToggle(boolean on); }

    private static final int[] RAINBOW = {
            0xFFFF4D4D, 0xFFFFD34D, 0xFF5CFF8F, 0xFF4FD6FF,
            0xFFA06CFF, 0xFFFF4D9E, 0xFFFF4D4D
    };

    private final Paint glow = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint ball = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint ring = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint sweep = new Paint(Paint.ANTI_ALIAS_FLAG);

    private int color = 0xFFFBB03F;
    private int brightness = 178;          // 0..255, the device's own range
    private boolean on = true;
    private String scene = "solid";

    private float phase = 0f;              // 0..1, drives breathe + rainbow
    private ValueAnimator animator;
    private OnPowerToggleListener listener;

    public BulbOrbView(Context c) { this(c, null); }

    public BulbOrbView(Context c, AttributeSet a) {
        super(c, a);
        ring.setStyle(Paint.Style.STROKE);
        ring.setStrokeWidth(dp(1));
        ring.setColor(0x24F6EDE2);
        setOnClickListener(v -> {
            on = !on;
            if (on && "off".equals(scene)) scene = "solid";
            syncAnimator();
            invalidate();
            if (listener != null) listener.onPowerToggle(on);
        });
    }

    public void setOnPowerToggleListener(OnPowerToggleListener l) { this.listener = l; }

    /** Mirrors the State characteristic (0xFF32) snapshot. */
    public void setBulbState(boolean on, int brightness, int color, String scene) {
        this.on = on;
        this.brightness = Math.max(0, Math.min(255, brightness));
        this.color = color;
        this.scene = scene == null ? "solid" : scene;
        syncAnimator();
        invalidate();
    }

    public boolean isOn() { return on && !"off".equals(scene); }

    private void syncAnimator() {
        boolean needs = isOn() && ("breathe".equals(scene) || "rainbow".equals(scene));
        if (!needs) {
            if (animator != null) { animator.cancel(); animator = null; }
            phase = 0f;
            return;
        }
        long period = "rainbow".equals(scene) ? 6000L : 3600L;
        if (animator != null) animator.cancel();
        animator = ValueAnimator.ofFloat(0f, 1f);
        animator.setDuration(period);
        animator.setRepeatCount(ValueAnimator.INFINITE);
        animator.setInterpolator(new LinearInterpolator());
        animator.addUpdateListener(a -> { phase = (float) a.getAnimatedValue(); invalidate(); });
        animator.start();
    }

    @Override protected void onAttachedToWindow() { super.onAttachedToWindow(); syncAnimator(); }

    @Override protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (animator != null) { animator.cancel(); animator = null; }
    }

    @Override protected void onDraw(Canvas canvas) {
        float cx = getWidth() / 2f, cy = getHeight() / 2f;
        float outer = Math.min(cx, cy);
        float r = outer - dp(26);
        if (r <= 0) return;

        float v = isOn() ? Math.max(0.12f, brightness / 255f) : 0f;
        float breathe = "breathe".equals(scene)
                ? 0.55f + 0.45f * (float) Math.abs(Math.sin(phase * Math.PI))
                : 1f;

        // Halo
        if (v > 0f) {
            int halo = withAlpha(color, (int) (170 * v * breathe));
            glow.setShader(new RadialGradient(cx, cy, outer,
                    new int[]{halo, withAlpha(color, 0)}, new float[]{0f, 1f}, Shader.TileMode.CLAMP));
            canvas.drawCircle(cx, cy, outer, glow);
        }

        // Body
        if (v > 0f) {
            int lit = blend(color, Color.WHITE, 0.32f * v * breathe);
            ball.setShader(new RadialGradient(cx, cy - r * 0.2f, r,
                    new int[]{lit, color, blend(color, Color.BLACK, 0.45f)},
                    new float[]{0f, 0.62f, 1f}, Shader.TileMode.CLAMP));
        } else {
            ball.setShader(new RadialGradient(cx, cy - r * 0.2f, r,
                    new int[]{0xFF2A211A, 0xFF17120E}, new float[]{0f, 1f}, Shader.TileMode.CLAMP));
        }
        canvas.drawCircle(cx, cy, r, ball);

        // Rainbow sweep, rotating at the ring's own rate
        if (isOn() && "rainbow".equals(scene)) {
            SweepGradient sg = new SweepGradient(cx, cy, RAINBOW, null);
            android.graphics.Matrix m = new android.graphics.Matrix();
            m.setRotate(phase * 360f, cx, cy);
            sg.setLocalMatrix(m);
            sweep.setShader(sg);
            sweep.setAlpha((int) (217 * Math.max(0.35f, v)));
            canvas.drawCircle(cx, cy, r, sweep);
        }

        canvas.drawCircle(cx, cy, r, ring);
    }

    private static int withAlpha(int c, int a) {
        return Color.argb(Math.max(0, Math.min(255, a)), Color.red(c), Color.green(c), Color.blue(c));
    }

    private static int blend(int a, int b, float t) {
        t = Math.max(0f, Math.min(1f, t));
        return Color.rgb(
                (int) (Color.red(a) + (Color.red(b) - Color.red(a)) * t),
                (int) (Color.green(a) + (Color.green(b) - Color.green(a)) * t),
                (int) (Color.blue(a) + (Color.blue(b) - Color.blue(a)) * t));
    }

    private float dp(float v) { return v * getResources().getDisplayMetrics().density; }
}
